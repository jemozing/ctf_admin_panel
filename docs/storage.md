# Ротация и квоты

Политика хранения задаётся локальным администратором в `executor.json`, секция `storage`. Dashboard не может менять лимиты или передавать пути/ID объектов для удаления.

```json
{
  "storage": {
    "manual_snapshots": 3,
    "candidate_snapshots": 3,
    "verified_releases": 3,
    "candidate_max_age_hours": 24,
    "snapshot_max_bytes": 17179869184,
    "staging_max_bytes": 8589934592,
    "state_max_bytes": 34359738368,
    "docker_max_bytes": 137438953472,
    "minimum_free_bytes": 268435456,
    "minimum_free_inodes": 1024,
    "build_reserve_bytes": 67108864
  }
}
```

Это значения по умолчанию, включая отсутствующие/нулевые поля. Размеры — байты; перед соревнованием настройте их по фактическим размерам сервисов. Резерв сборки — предварительная оценка, а не обещание точного размера image/cache. Лимиты панели не ограничивают память и диск всех дочерних шагов BuildKit на уровне kernel.

## Защищённые объекты

Ротация проверяет все ссылки из текущего состояния и незавершённых задач, а не только возраст каталогов. Сохраняются:

- Все baseline и первоначальные импортированные релизы.
- Фактически активный релиз и дерево, в том числе между сменой политики и созданием нового baseline.
- Три предыдущих релиза с успешной **локальной функциональной** проверкой. Docker Running/healthcheck сам по себе такую отметку не создаёт.
- Последний source-кандидат, snapshots с явными pins, кандидаты и релизы queued/running/interrupted/requires_recovery операций.
- Recovery point и ссылки его состояния до подтверждённого завершения операции.
- Каталог метаданных после metadata-only restore до новой локальной проверки регистрации.

Manual snapshots имеют отдельную очередь: сохраняются три последних незакреплённых снимка. Для неиспользованных кандидатов и неподтверждённых prepared releases действуют отдельные count/age ограничения. Они не вытесняют проверенные версии. При нехватке места можно удалить дополнительные **незащищённые** manual/candidate объекты; если этого недостаточно, новая операция завершается ошибкой до переключения приложения.

Ротация запускается в worker до и после операций; при превышении квоты дополнительно выполняется сбор незакреплённых объектов. После неизвестного исхода сохраняются блокировки и артефакты восстановления. Ошибка фоновой очистки после уже записанного результата не превращает успешный Deploy в ложный сбой; публикуется maintenance warning, очистка повторяется позднее.

## Удаление и аварии

Перед физическим удалением в FULL SQLite сохраняется неизменяемая tombstone-запись. Такой снимок/релиз сразу становится недоступен для новых операций, даже если удаление ещё не завершено. Каталог снимка проверяется, атомарно переименовывается в приватный `.trash-*`, синхронизируется и удаляется через descriptor-relative API. После аварии очистка продолжается; symlinks, hardlinks, специальные файлы, смена mount и повреждённые защищённые артефакты не обходятся автоматически.

Рабочие каталоги получают durable allocation receipt **до** создания. Janitor очищает только зарегистрированные allocations завершённых операций; незавершённые и неизвестные каталоги не объявляются мусором по одному имени. Частичные unpublished snapshots тоже учитываются квотой и могут безопасно очищаться по receipt после завершения задачи. Старые каталоги без receipt остаются видимыми в общем расходе и требуют локального разбора администратора.

После retirement релиза удаляются только его уникальные `ctf-manager/<service>:<release>-<component>` retention tags с совпавшим image ID. Force, удаление по image ID и общий Docker prune не используются. Внешние теги, volumes, игровые данные и общий build cache не очищаются. Неопубликованные результаты прерванных Docker builds могут остаться в daemon cache/образах: они входят в общий Docker budget, но автоматическое удаление неинвентаризированных результатов не выполняется.

## Предварительные проверки

Подсчёт logical bytes/entries проходит по метаданным через descriptor-relative API. В Linux обычные файлы проверяются с `O_PATH|O_NOFOLLOW`: открытие/закрытие обычного I/O FD активной SQLite БД в процессе writer снимало бы её POSIX locks. В Darwin development используется `Root.Lstat`. Проверки inode/mode/size/mtime, hard links, symlinks и Linux mount ID сохраняются. Межпроцессный [regression](../tests/integration/reports/README.md#report-sqlite-wal-lock-safety-2026-10-20-json) подтверждает, что quota scans не удаляют активные WAL/SHM и не скрывают commits от других SQLite-процессов.

Перед snapshot и staging проверяются:

- Логический размер файлов, metadata и всего executor state.
- Доступное место и запас inode на соответствующей файловой системе.
- Размер нового управляемого дерева до копирования; изменение дерева между расчётом и Capture отклоняется.
- Квота снова проверяется перед публикацией готового снимка.
- Перед Build и переключением — общий учтённый расход Docker images/cache/containers/volumes через Engine API.

Квоты logical bytes не равны физическому выделению sparse/compressed файлов. Расчёт — preflight, а не kernel reservation: другой процесс может заполнить ФС после проверки. Настоящий ENOSPC до мутации оставляет неполный unpublished артефакт; после начала переключения действует обычный recovery pipeline.

Для физического free-space/inode контроля **Docker storage** нужен явно разрешённый read-only bind его data root. Bootstrap поддерживает `--docker-storage-root /var/lib/docker` (или фактический custom root). Executor сверяет путь с `DockerRootDir` daemon. Без такого mount JSON status явно не содержит `docker_capacity`; лимит логического расхода daemon остаётся активен. Свободное место контейнерного `/` не выдаётся за свободное место Docker host. Не монтируйте `/` и не добавляйте Docker storage в dashboard.

## CLI

Executor должен быть запущен; команды обращаются к его Unix API и используют ту же сериализацию, что worker:

```sh
bin/ctf-manager --config var/executor.dev.json storage
bin/ctf-manager --config var/executor.dev.json rotate
```

Для Compose:

```sh
docker compose --env-file /srv/ctf-manager/config/compose.env exec executor \
  ctf-manager --config /etc/ctf-manager/executor.json storage
docker compose --env-file /srv/ctf-manager/config/compose.env exec executor \
  ctf-manager --config /etc/ctf-manager/executor.json rotate
```

`storage` показывает effective limits, usage/capacity, предстоящую ротацию и причины pins. `rotate` выполняется только для локального UID администратора executor; Web UID получает отказ. Вводить произвольные пути или списки удаления нельзя. Изменение `executor.json` требует перезапуска executor и нового просмотра плана операции.

## Свидетельства

[Сквозной smoke ротации/квот/backup](../tests/integration/reports/README.md#report-release-storage-backup-smoke-2026-10-19-json) подтверждает manual6 → latest3, сохранение baseline/imported release, отказ при лимите snapshot 1 byte до active mutation и полный CLI backup/restore. [Storage pressure](../tests/integration/reports/README.md#report-storage-pressure-2026-10-19-json) содержит настоящие ENOSPC на tmpfs 1 MiB и дефицит inode. Эти проверки не закрывают все аварии SQLite/Docker или performance matrix.
