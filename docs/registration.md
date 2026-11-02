# Регистрация существующего Compose-проекта

Регистрация выполняется Admin через панель или дополнительным локальным CLI. JSON от web-клиента не становится доверенной политикой без проверки executor. Процесс регистрации сначала сохраняет неизменяемое предложение, затем администратор подтверждает его digest в панели. При подтверждении повторно проверяются фактические контейнеры, образы, сети и mounts. CLI-подтверждение для веб-сценария не требуется.

## Добавление через панель

1. Войдите как Admin и нажмите «Добавить сервис» на странице сервисов.
2. Нажмите «Выбрать папку», откройте разрешённый каталог Docker-хоста, перейдите в папку проекта и нажмите «Выбрать эту папку». Можно также ввести абсолютный host-путь вручную, без кавычек и завершающего `/`. Каталог должен находиться внутри подключённого при установке discovery root; корни показаны в форме. Контейнеры проекта должны уже существовать, чтобы сохранить их фактическую идентичность и исходные параметры Compose. Импорт нового ещё не запущенного проекта не входит в этот сценарий.
3. Проверьте название, предложенные роли компонентов, цели обновления и управляемые пути. Панель не требует ручного JSON. Workspace создаётся автоматически в разрешённом workspace root.
4. Проверьте все хранилища. Значимые данные оставьте постоянными; для writable layer и допустимых временных данных явно подтвердите допустимость потери. Неизвестное расположение флагов требует выяснения до подтверждения. Проекты с неподдерживаемыми mounts/runtime блокируются с диагностикой.
5. Просмотрите неизменяемую заявку и подтвердите её в панели. Подмена digest или обнаруженных Docker/Compose идентификаторов отклоняется.
6. Панель поставит baseline/импортированный релиз и заполнение source workspace в очередь. Отдельная операция показывает готовность или ошибку инициализации. Регистрация, снимок и копирование исходников не перезапускают контейнеры. Повтор подтверждения не создаёт второй сервис.
7. При необходимости укажите HTTPS Git URL, ref, подкаталог и read-only токен. Источник также можно настроить позже в карточке сервиса. Получение Git-кандидата — отдельная операция, после которой выполняются Build и Deploy; локальные правки workspace используют Prepare.

Разрешённые корни подключаются к executor один раз при установке через Compose bootstrap. Панель не получает доступ к произвольному host-пути только по введённой строке. Для нового корня потребуется изменить конфигурацию установки; для каждого сервиса внутри существующего корня CLI не нужен.

Выбор папки показывает файловую систему Docker-хоста через executor. Есть переход в подпапку, «Выше», «Все каталоги», обновление и ручной ввод. Список содержит только настоящие каталоги; символические ссылки не показываются и не открываются. Рядом с текущим путём отображаются имена найденных стандартных файлов `compose.yaml`, `compose.yml`, `docker-compose.yaml`, `docker-compose.yml`. Их содержимое не читается. Подсказка не подтверждает совместимость Compose или наличие контейнеров; это проверяется действием «Найти сервис».

Листинг ограничен 4096 просмотренными записями, 256 возвращёнными каталогами и 64 КиБ имён/путей. Усечённый список явно отмечен; для отсутствующей в нём папки сохранён ручной ввод. Открытие недоступного mount или изменённого пути завершается ошибкой, выбор устаревшего списка во время навигации/обновления блокируется. Просмотр папок не создаёт каталоги, заявки или Docker-контейнеры и не меняет права.

GitHub/GitLab поддерживаются по HTTPS Git URL без API провайдера. В этом профиле сервер должен разрешаться только в публичные адреса и иметь доверенный TLS-сертификат. SSH, GitLab во внутренней сети, webhooks и polling остаются последующими расширениями. Парольный токен не возвращается интерфейсу и хранится отдельно в vault.

`internal/policy.ValidateRegistration(config, service, composeReport, containers)` возвращает `*RegistrationError` с детерминированным списком блокирующих `Issues`; `RegistrationIssues` предоставляет тот же список для CLI/API. В диагностике не выводятся environment, command и содержимое секретов. Любой Issue из ComposeReport запрещает одобрение. Разбор нормализованной модели повторяется, чтобы удаление публичного списка Issues не обходило проверку.

## Требования к карте

1. Active project и source workspace существуют в отдельных разрешённых bootstrap-каталогах. Они не перекрываются и не являются alias через symlinks. Source workspace находится вне всех game bind mounts, включая mounts только для чтения.

   Если первый baseline должен заполнить **пустой** source workspace, этот каталог должен принадлежать executor и иметь права `0700`. Для production executor это UID 0. Каталог с правами `0755` не переоформляется автоматически: безопасная материализация завершится отказом. Существующие авторские файлы baseline не перезаписывает.
2. Compose project name, набор файлов и profiles явно совпадают с нормализованным входом. Нормализованный document, его SHA-256 и публичная карта компонентов должны согласовываться.
3. Каждый Compose-компонент имеет ровно один подтверждённый полный container ID, неизменяемый image ID и роль. Inventory содержит тот же набор компонентов и project/service labels. Реплики в начальном профиле не поддерживаются.
4. Каждый фактический mount совпадает с Compose по target, type, source identity и read-only. Named volume сопоставляется через `volumes.<logical>.name`, а в DataPath хранится фактическое Docker-имя. Известный image-declared mount, отсутствующий в Compose, тоже блокирует recreation: сохранение такого mount нужно явно закрепить в конфигурации.
5. Bind кода/конфигурации разрешён только с source, точно равным одному утверждённому ManagedPath внутри active project. Произвольный подкаталог разрешённого дерева автоматически не становится разрешённой точкой монтирования. Остальные mounts требуют DataPath с точным component/target/source.
6. Significant data отделены от управляемого кода и source workspace. Они сохраняются во внешнем bind/named volume. Anonymous volume, tmpfs и writable layer с significant data блокируют регистрацию для recreation до миграции.
7. У **каждого** компонента есть явная запись `kind=writable_layer`, `significant=false`, `loss_accepted=true`. Она означает осознанное принятие потери всего оставшегося слоя после выноса значимых данных. Target в текущем domain указывает исследованный путь, например `/tmp`; `/` не является допустимым DataPath. Эта запись не является автоматическим доказательством отсутствия других данных. При неполном исследовании registration остаётся отклонённой.
8. Targets содержат только зарегистрированные компоненты. Зависимость БД не включается в обновление приложения автоматически.

Пример фрагмента карты хранения:

```json
{
  "data_paths": [
    {
      "name": "database",
      "kind": "named_volume",
      "source": "team_service_database-data",
      "target": "/data",
      "component": "database",
      "significant": true,
      "loss_accepted": false
    },
    {
      "name": "app-layer",
      "kind": "writable_layer",
      "target": "/tmp",
      "component": "app",
      "significant": false,
      "loss_accepted": true
    },
    {
      "name": "database-layer",
      "kind": "writable_layer",
      "target": "/tmp",
      "component": "database",
      "significant": false,
      "loss_accepted": true
    }
  ],
  "targets": ["app"]
}
```

## Файловые ограничения

В production родительские каталоги host bind sources и зарегистрированных roots должны принадлежать root/executor, не иметь group/world write и не принадлежать web UID. Родитель bind source не может находиться внутри другого writable game bind. Запрещены host control paths (`/proc`, `/sys`, `/dev`, Docker storage/socket и другие системные каталоги), executor state и управляющие файлы. Ссылки в managed roots и Compose filenames отклоняются. Для ещё не созданного managed файла source workspace проверяются существующие родители: отсутствие leaf не должно скрывать symlink ancestor.

Development mode позволяет проверять логику в пользовательском каталоге и OS temp roots. Он **не подтверждает** production ownership isolation. Регистрация на macOS/OrbStack не заменяет проверку Linux, разных UID, Unix socket и systemd.

Validation использует файловую систему в момент проверки и ничего не изменяет. Она не удерживает открытые дескрипторы до будущего действия и не устраняет TOCTOU сама по себе. Snapshot, подготовка и переключение обязаны повторно открывать пути относительно доверенных roots, проверять каждый entry/symlink/hardlink и повторять policy validation перед использованием. По одной проверке имён путей нельзя обещать безопасность последующего удаления или записи.

## Сопоставление фактического runtime

Executor получает `ContainerInspect`, `ImageInspect` по неизменяемому image ID, `NetworkInspect` и `VolumeInspect` для каждого фактического named volume. При одобрении сравнивается эффективная конфигурация Compose с параметрами контейнера:

- environment после наследования image ENV, переопределения и удаления значений через Compose;
- command/entrypoint, включая явные пустые списки и сброс image CMD при заданном entrypoint;
- user, working directory, hostname/domainname, stop signal/timeout, tty/stdin и init;
- healthcheck test, интервалы, timeout, start period/interval, retries и отключение, с наследованием из образа;
- read-only rootfs, cap_drop и no-new-privileges; отсутствие дополнительных capabilities, devices и host namespaces;
- published/exposed ports, driver и точные подключения к project-owned bridge networks, aliases и отсутствие скрытых статических IP-настроек;
- CPU, memory/swap/reservation, PID limits, cpuset, restart policy, shared memory и поддерживаемая конфигурация ротации логов;
- пользовательские labels, точные type/source/target/read-only всех mounts и отсутствие неподдерживаемых mount options;
- backing metadata named volumes: только local driver/scope без driver options, с точным фактическим mountpoint. Проверяются также external volumes: `external: true` не разрешает скрытые local-driver bind mounts к каталогам хоста.

Значения environment, command, healthcheck и inspect остаются в приватных полях адаптера. `json.Marshal(Container)` публикует только прежнюю карту inventory; обратная десериализация не восстанавливает доказательства runtime. `ValidateRegistration` отклоняет такой DTO с `runtime_inspection_missing`. Изменение нормализованного документа также не позволяет использовать чужое inspection evidence: private IDs, image ID и project/service labels повторно сопоставляются с публичной картой.

MVP принимает обычные Linux defaults и явно поддержанные Compose settings. Дополнительные service keys, runtime security settings, external/custom-driver networks, custom IPAM, daemon bridge mode и неизвестные resource/mount options блокируют регистрацию. Новые поля должны получить явное сопоставление до включения в профиль. Engine-generated network IP/subnet, container ID/hostname и служебные Compose labels учитываются отдельно от пользовательской конфигурации. Публичная диагностика называет настройку и код ошибки, а значения не показывает.

Если daemon использует нестандартные defaults shared memory или logging options, их нужно явно закрепить в Compose, например:

```yaml
shm_size: 64m
logging:
  driver: json-file
  options:
    max-size: "20m"
    max-file: "5"
```

Так import не принимает параметры, которые не сможет воспроизвести. Синтетические fixtures используют явные shared memory/log rotation settings. Compose 5 может добавлять пустой `networks.default.ipam: {}`; это эквивалент стандартного IPAM и допускается. Непустой custom IPAM отклоняется.

Сравнение остаётся проверкой состояния в момент inspection. Оно не заменяет проверку перед переключением релиза и сверку после аварии. Изменения ресурсов внешней командой между inspection и действием должны повторно обнаруживаться операцией.

## Локальный workflow

```sh
bin/ctf-manager --config /etc/ctf-manager/executor.json inventory --project team_service
bin/ctf-manager --config /etc/ctf-manager/executor.json inspect-project \
  --directory /srv/ctf/services/team_service --project team_service --files compose.yaml
bin/ctf-manager --config /etc/ctf-manager/executor.json propose --service registration.json
bin/ctf-manager --config /etc/ctf-manager/executor.json approve \
  --proposal proposal-ID --digest sha256:REVIEWED_DIGEST
bin/ctf-manager --config /etc/ctf-manager/executor.json services
```

Перед approve читается конкретное предложение и проверяются source/data/component maps. Digest другой версии предложения отклоняется. Propose/approve не пересоздают контейнеры. Повторное чтение IDs подтверждает отсутствие изменений; отдельный интеграционный smoke проверяет этот workflow на синтетическом named-volume сервисе. Полные deploy/rollback и снимки не входят в данную проверку регистрации.

Чистые проверки без Docker:

```sh
make test
# или только policy с writable Go caches:
GOCACHE="$PWD/.cache/go-build" GOMODCACHE="$PWD/.cache/go-mod" go test -race ./internal/policy
```


Интеграционная проверка в разработческой среде с доступным локальным Docker:

```sh
make build
python3 tests/integration/registration_smoke.py
```

Нужен `var/executor.dev.json` с discovery root `var/fixtures`, workspace root `var/workspaces` и приватным `var/executor`. Smoke создаёт отдельный `ctfm-reg-smoke-<run-id>`, предварительно проверяет loopback-порты и mounts, строит только bundled named-volume fixture. Затем выполняет inventory → propose → отказ на неверном digest → approve → services. После регистрации сверяет IDs, image IDs, mounts, тестовую запись и время запуска целевых контейнеров. Изменения времени запуска посторонних контейнеров фиксируются отдельно как внешнее наблюдение: другие проекты не замораживаются этим smoke. По умолчанию останавливает только свой проект без удаления volume. `--keep` оставляет его работать для осмотра.

Карта, предложение и JSON-отчёт сохраняются только в `var/registration-runs/<run-id>/`. Запись в registry также остаётся в разработческой БД; её description обозначает тест и последующую остановку контейнеров. Smoke не проверяет production isolation, baseline, подготовку релиза или deploy/rollback.


Проверенный прогон 19.10.2026: [registration-smoke-2026-10-19.json](../tests/integration/reports/README.md#report-registration-smoke-2026-10-19-json) — PASS на Docker Engine 29.8.2 / Compose 5.5.0 / OrbStack Linux arm64. Неверный digest отклонён; после approve регистрация сохранена, целевые IDs, image IDs, mounts, StartedAt и синтетический флаг не изменились. После проверки остановлен только новый тестовый проект, named volume сохранён. Два посторонних контейнера меняли StartedAt в фоне; это отражено как `external_observation`, а не как действие или гарантия этого smoke.


После добавления runtime reconciliation повторный прогон 19.10.2026: [runtime-registration-smoke-2026-10-19.json](../tests/integration/reports/README.md#report-runtime-registration-smoke-2026-10-19-json) — PASS на том же Engine/Compose. Регистрация сопоставила private container/image/network inspection с frozen Compose; ID, mounts, StartedAt и синтетический флаг сохранены. Все три fixture прошли [runtime-fixtures-smoke-2026-10-19.json](../tests/integration/reports/README.md#report-runtime-fixtures-smoke-2026-10-19-json): named/bind storage пережили recreation, потеря writable-layer данных обнаружена ожидаемо. Внешние изменения контейнеров отражены отдельно; в это время параллельно завершался созданный данной проверкой диагностический проект.
