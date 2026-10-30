# Установка через Docker Compose

Основной профиль — Linux Docker-хост и два контейнера: `dashboard` (HTTP, UI, пользователи) и `executor` (политики, Docker, снимки и релизы). Состояние сохраняется на хосте. Игровые сервисы остаются отдельными Compose-проектами.

Эта инструкция описывает способ установки разрабатываемого MVP. Полноту операций и проверенную матрицу совместимости нужно сверять с [текущим прогрессом](progress.md).

HTTP reverse proxy, recorder, страница трафика и WAF **пока запланированы** в [отдельном расширении](http-proxy-waf-plan.md). Будущий opt-in Compose-проект proxy должен работать независимо от проекта панели, чтобы её остановка/обновление не прерывали игровые HTTP-маршруты. В существующем `compose.yaml` эти компоненты сейчас отсутствуют.

Подключение к уже занятым игровым портам потребует отдельного Admin-плана cutover/rollback с обновлением утверждённой runtime policy. Обычная установка MVP, добавление записи маршрута или Deploy кода сами по себе не переназначают порты и не меняют firewall. Отказ recorder не должен останавливать пересылку; отказ самого proxy требует восстановления по сохранённой процедуре.

## Подготовка

Нужны Linux, Docker Engine, Docker Compose plugin и Python 3.10+. Первая сборка скачивает Go/npm-зависимости и базовые образы; подготовленный образ панели запускается без компиляторов и Node.js. Для работы с Docker требуется локальный Unix socket. Удалённый daemon и rootless/userns-remap профиль не входят в текущую Linux-приёмку.

Запустите bootstrap на самом Docker-хосте из checkout проекта:

```sh
python3 scripts/compose-bootstrap.py --dry-run \
  --host-metrics \
  --discovery-root /srv/game-services \
  --workspace-root /srv/ctf-workspaces

sudo python3 scripts/compose-bootstrap.py \
  --host-metrics \
  --discovery-root /srv/game-services \
  --workspace-root /srv/ctf-workspaces
```

Указанные существующие корни должны быть каноническими абсолютными каталогами без symlink-компонентов. Bootstrap не копирует и не изменяет проекты, не запускает Docker и не меняет их владельцев. Без флагов он создаёт пустые `/srv/ctf-manager/services` и `/srv/ctf-manager/workspaces`; регистрировать можно только проекты внутри явно разрешённых корней. Для нескольких корней повторите соответствующий флаг. Не используйте `/`, `/home` целиком или общий каталог с секретами.

По умолчанию bootstrap создаёт:

| Host-путь | Владелец/права | Назначение |
|---|---|---|
| `/srv/ctf-manager/config` | `0:0`, `0700` | Root-owned JSON executor, env и mount override |
| `/srv/ctf-manager/dashboard` | `10001:10001`, `0700` | БД пользователей и сессий |
| `/srv/ctf-manager/executor` | `0:0`, `0700` | Доверенная БД, снимки, релизы, секреты |
| `/srv/ctf-manager/runtime` | `0:10001`, `0750` | Unix socket `0660` |

Другой служебный корень задаётся `--root /absolute/dedicated/path`; его родитель должен существовать. При повторном запуске корректные каталоги и идентичные конфигурации сохраняются. Несовпадающие конфигурации требуют предварительного просмотра и `--replace-config`; БД и артефакты этот флаг не сбрасывает. При несовпадении владельцев/прав bootstrap завершается ошибкой и не исправляет рекурсивно содержимое.

Для физического запаса места и inode именно на диске Docker укажите отдельный
`--docker-storage-root /var/lib/docker`, предварительно сверив фактический
`DockerRootDir` своего daemon. Пример с нестандартным хранилищем:

```sh
sudo python3 scripts/compose-bootstrap.py --dry-run \
  --docker-storage-root /mnt/docker-data
```

Флаг добавляет `docker_storage_directory` в bootstrap и read-only bind с тем же
абсолютным source/target только в executor. Каталог должен существовать, не
содержать symlink-компонентов и не пересекаться с installation/service/workspace
roots. Bootstrap не определяет DockerRootDir автоматически и не меняет этот
каталог. Executor сверяет путь с Docker Info до использования Statfs: указать
другой диск как будто это Docker data root нельзя. Без флага daemon-wide логическая
занятость измеряется через Docker API, а физический запас места Docker отмечается
как неизвестный; контейнерный rootfs не выдаётся за файловую систему daemon.
Подробнее о квотах — [управление хранилищем](storage.md).

Флаг `--host-metrics` добавляет только executor пять отдельных read-only procfs
файлов хоста: CPU, memory, load, uptime и сеть host PID 1. Ни host namespaces,
ни mount всего `/proc` не требуются. Источники, семантика CPU и часовая история
описаны в [инструкции метрик](metrics.md). Без флага host procfs-показатели
недоступны; файловые системы измеряются по уже разрешённым путям.

В каталоге `config/` генерируются `executor.json`, `compose.mounts.yaml` и `compose.env`. Последний задаёт `COMPOSE_FILE` основного Compose и mount override, поэтому дальше достаточно `--env-file`:

```sh
sudo docker compose --env-file /srv/ctf-manager/config/compose.env config --quiet
sudo docker compose --env-file /srv/ctf-manager/config/compose.env build
```

Перед первым запуском создайте администратора локальным `init-admin` в образе dashboard. Пароль длиной 12–1024 байта читается из stdin; стандартного пароля, регистрации через web или переменной `ADMIN_PASSWORD` нет. В bash/zsh можно ввести пароль без отображения на экране и без записи в history:

```sh
sudo -v
read -r -s CTFM_INITIAL_PASSWORD
printf '%s\n' "$CTFM_INITIAL_PASSWORD" | \
sudo docker compose --env-file /srv/ctf-manager/config/compose.env \
  run --rm --no-deps -T dashboard init-admin \
  --state /var/lib/ctf-manager --username admin
unset CTFM_INITIAL_PASSWORD
```

После ввода нажмите Enter. Переменная не экспортируется в окружение контейнера; CLI не выводит пароль. `init-admin` работает только при отсутствии пользователей и не сбрасывает существующие учётные записи. Для автоматизации доступен `--password-file` с приватным файлом, доступным внутри контейнера; значения пароля в аргументах нет. При использовании `sudo` сначала выполните `sudo -v`, чтобы его запрос не конкурировал с stdin пароля.

После bootstrap администратора:

```sh
sudo docker compose --env-file /srv/ctf-manager/config/compose.env up -d --build
sudo docker compose --env-file /srv/ctf-manager/config/compose.env ps
```

Учётные записи сохраняются в state. При перезапуске HTTP-процесса все прежние сессии отзываются: участники входят снова. Повторный `init-admin` не отзывает сессии и не меняет пользователей.

Dashboard доступен на `http://127.0.0.1:8765`. Для доступа с рабочей станции:

```sh
ssh -N -L 8765:127.0.0.1:8765 team@vulnbox
```

Внутри контейнера HTTP слушает `0.0.0.0:8765`; публикация Compose ограничена loopback хоста. Для HTTPS reverse proxy задайте в `compose.env` `CTFM_ALLOWED_HOSTS` с точными Host, включая нестандартный порт, и `CTFM_SECURE_COOKIES=true`; локальный healthcheck сохраняет `127.0.0.1:8765` в allowlist. Для loopback/SSH используется `CTFM_SECURE_COOKIES=false`. Не публикуйте HTTP в публичный интерфейс изменением только `CTFM_BIND_ADDRESS`.

## Что получает каждый контейнер

Dashboard работает с UID/GID `10001:10001`, read-only rootfs, `cap_drop: ALL` и `no-new-privileges`. В нём нет Docker CLI. Он видит собственный state как `/var/lib/ctf-manager` и read-only каталог `/run/ctf-manager` с Unix socket. Сокет допускает подключение клиента, read-only mount не даёт клиенту заменить файл socket.

Executor работает с UID `0`, GID `10001`. Root нужен для чтения/восстановления файлов разных владельцев. Docker socket монтируется только сюда. Capabilities ограничены CHOWN/DAC_OVERRIDE/FOWNER; privileged и host PID/network namespaces не используются. У обоих контейнеров read-only rootfs; временные файлы размещаются в ограниченных tmpfs.

Доступ к Docker socket означает высокие полномочия на хосте. Их ограничивают проверяемая политика executor, типизированные операции, проверка UID клиента и отсутствие произвольных команд в web API. Контейнер сам по себе не превращает Docker API в непривилегированный интерфейс. [Docker Engine security](https://docs.docker.com/engine/security/).

Dashboard не монтирует каталоги игровых сервисов, исходники, снимки, секреты, конфигурацию и БД executor. Общего volume со всем состоянием панели нет. Compose использует `create_host_path: false`, поэтому пропущенный bootstrap даёт ошибку mount вместо создания пустых каталогов с неожиданным владельцем. [Описание bind mounts Compose](https://docs.docker.com/reference/compose-file/services/#volumes).

Все approved roots и state executor имеют одинаковые абсолютные пути на хосте и внутри executor. Например, host `/srv/game-services` смонтирован в `/srv/game-services`. Docker daemon разрешает пути bind mounts на своём хосте, поэтому менять target на `/app/services` нельзя. Это правило относится и к подготовленным файлам, которые передаются daemon при применении релиза. [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/).

## Диагностика и локальное администрирование

```sh
sudo docker compose --env-file /srv/ctf-manager/config/compose.env logs --tail 100 dashboard executor
sudo docker compose --env-file /srv/ctf-manager/config/compose.env exec executor \
  ctf-manager --config /etc/ctf-manager/executor.json doctor
sudo docker compose --env-file /srv/ctf-manager/config/compose.env exec executor \
  ctf-manager --config /etc/ctf-manager/executor.json status
```

У executor healthcheck проверяет собственный Unix API; dashboard `/healthz` проверяет процесс HTTP. Успешный healthcheck панели не означает успешную функциональную проверку игровых сервисов. Состояние executor и локальные проверки сервисов отображаются отдельно. Dashboard запускается после готовности executor; при последующем отключении executor HTTP остаётся доступным с диагностикой.

HTTP-проверки игровых сервисов выполняются из bridge-сети executor. Укажите адрес, доступный оттуда: `127.0.0.1` внутри executor относится к самому контейнеру. Порт, опубликованный только на loopback хоста, не становится доступным через Docker gateway. Панель не перепривязывает игровые порты и не включает host networking ради проверки. При отсутствии доступного адреса оставьте локальную проверку не настроенной до отдельного решения администратора. Native smoke с host-loopback URL не подтверждает тот же URL в контейнерной установке.

Для регистрации войдите как Admin и используйте «Добавить сервис»: укажите host-путь внутри уже подключённого discovery root, проверьте обнаруженную конфигурацию и подтвердите заявку в панели. Workspace и baseline инициализируются автоматически отдельной операцией; игровые контейнеры не перезапускаются. Добавлять сервис через JSON/CLI не требуется. `propose`/`approve` через `exec executor` остаются дополнительным локальным способом администрирования. Подробности — в [порядке регистрации](registration.md).

HTTPS Git URL настраивается через панель. Образ executor содержит Git; Git subprocess запускается с отдельным непривилегированным UID/GID и без дополнительных групп. Для сброса привилегий executor получает `SETUID`/`SETGID`, а `KILL` позволяет остановить дочерний Git-процесс другого UID при таймауте/ошибке; dashboard эти capabilities не получает. Сеть нужна только для получения кандидата/сборки, rollback не обращается к Git. Private-network Git-серверы и SSH в этом профиле не поддерживаются.

Для изменения approved roots повторите bootstrap с полным новым списком, просмотрите конфигурацию и используйте `--replace-config`, затем пересоздайте только executor. Изменение корня состояния с уже зарегистрированными релизами требует отдельного переноса и проверки host-путей; простая смена переменной не является миграцией.

## Остановка, обновление и данные

```sh
sudo docker compose --env-file /srv/ctf-manager/config/compose.env stop
sudo docker compose --env-file /srv/ctf-manager/config/compose.env up -d --build
```

Эти команды затрагивают проект `ctf-manager`; игровые контейнеры продолжают работать. Compose project name панели нельзя менять на имя игрового проекта. Executor получает время на корректную остановку. Незавершённые операции после аварии сверяются с фактическим состоянием; их нельзя объявлять успешными по факту перезапуска процесса.

БД и файлы панели переживают замену образов, `stop` и `down`. Не удаляйте служебный host-каталог и не копируйте отдельно работающий SQLite `.db` при наличии WAL. Для согласованного экспорта и восстановления доступны локальные команды `backup`/`restore` с maintenance locks; перед экспортом останавливаются оба процесса панели. Порядок и область копии описаны в [инструкции резервирования](backup.md). Docker-образы игровых релизов хранятся daemon отдельно: резервная копия каталога панели сама по себе их не содержит.

Лимиты Compose ограничивают процессы панели, но не потребление ресурсов сборкой у Docker daemon. В MVP также проверяются лимиты build и свободное место под образы. Контейнерные `/proc` и `/sys` не выдаются за метрики хоста: недоступные источники отмечаются явно, расширенные host-mounts не включаются автоматически.

## Проверки упаковки

```sh
make packaging-check
docker compose build
python3 tests/integration/compose_smoke.py
```

Smoke создаёт отдельный случайно названный Compose-проект и временный native Docker volume, чтобы проверить Linux UID/GID даже при клиенте на macOS. Volume монтируется по своему точному daemon-side абсолютному пути. В тесте нет зарегистрированных игровых проектов: проверяются встроенный frontend, первый администратор, сессия/CSRF, IPC, разделение mounts/UID и восстановление executor после SIGKILL. После проверки проект и volume удаляются, результат записывается в [compose-smoke-2026-10-19.json](../tests/integration/reports/README.md#report-compose-smoke-2026-10-19-json).

Этот smoke не заменяет приёмку Linux host bind mounts с игровыми данными и целевой архитектуры linux/amd64. Общие файловые каталоги macOS могут не сохранять требуемые Linux владельцев/группы; production bootstrap должен отклонять такой каталог вместо ослабления прав.

## Независимые лимиты очереди

Bootstrap принимает `--max-builds 1 --max-copies 1 --max-switches 1` (каждое значение 1..4). Он записывает секцию `scheduler` в root-owned executor configuration. При отсутствии секции старые установки получают те же значения по умолчанию. Изменение применяется при следующем запуске executor; оно не меняет игровые Compose-проекты.

Долгие сборки, загрузки исходников и прогрев независимых сервисов могут выполняться параллельно. Копирование, выделение места, GC, публикация и критическое переключение сохраняют общий artifact gate. Rollback/Recover получают приоритет перед новыми сборками без прерывания активного переключения. Гарантии reservations, limits и границы такого параллелизма описаны в [scheduler.md](scheduler.md).
