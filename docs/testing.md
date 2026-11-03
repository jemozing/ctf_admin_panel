# Тестовый стенд и приёмочные прогоны

Публикуемые результаты собраны в [обезличенной сводке](../tests/integration/reports/README.md) и [машинном summary](../tests/integration/reports/public-summary.json). Исходные отчёты и скриншоты не входят в Git. Команды `--report` ниже создают новые локальные артефакты; наличие такой команды не означает успешной приёмки.

## Регистрация writable bind-кода

```sh
make frontend frontend-check
go test -race ./internal/domain ./internal/policy ./internal/executor ./internal/transport ./internal/dashboard
node tests/integration/writable_bind_browser_smoke.cjs
```

Browser smoke требует Playwright/Chromium и использует собранный React UI с синтетическим API на loopback. Проверяются оба shared root binds, отдельное согласие, цели обновления, повторный расчёт/ошибки и финальный review. Executor-тесты используют настоящие snapshots, MaterializeBuild и Apply/обратный Apply с остановленным gate, проверяют code add/delete, исключения DB/uploads/.env и файловую provenance root bind при одинаковых images. Это не настоящий Compose Build/Deploy/Rollback; реальный Docker/VM для этих прогонов не используются.

## Окна действий при HTTP-доступе по сетевому адресу

```sh
make frontend frontend-check
node tests/integration/action_dialog_http_smoke.cjs
```

Для browser smoke нужны установленный Playwright и Chromium; скрипт также умеет использовать локальный кэш среды Codex и ничего не скачивает. Сервер слушает только loopback, а Chromium открывает HTTP-имя `ctfm-dialog.test`, явно сопоставленное с loopback. Так проверяется настоящий insecure context: `randomUUID` отсутствует, `getRandomValues` доступен. Проверка через `localhost` этот дефект не воспроизводит.

Используется собранный frontend и синтетический HTTP API: открытие «Подготовить»/«Применить», отдельное подтверждение, смена релиза, сохранение ключа между preview/submit, новый ключ после закрытия и видимая ошибка preview. Это UI-регрессия; настоящие executor, Deploy/Rollback, Docker и VM в ней не используются.

## Проверка Git и выбор ветки

```sh
make build
go test -race ./internal/sourcegit ./internal/executor ./internal/transport ./internal/dashboard
python3 tests/integration/git_probe_process_smoke.py \
  --manager-binary bin/ctf-manager --report var/git-probe-browser.json
```

Sourcegit-тесты используют настоящий Git и локальный TLS fixture с приватным CA только внутри test runner; production bypass для TLS/DNS не добавляется. Проверяются auth, refs, redirect, отмена, переполнение реального stdout и отсутствие загруженных objects. Для browser smoke нужны Node.js и имеющиеся Playwright/Chromium (либо cached Codex runtime). Он запускает настоящий dashboard, Admin через stdin и синтетический Unix executor: это проверка UI-контракта, без внешней сети/GitHub, Git, Docker или регистрации сервиса. Отчёт не содержит credentials, локальных путей и логов. Для повторного запуска укажите новый путь отчёта.

Успешный UI fixture не подтверждает доступ к публичному Git-серверу. Production probe дополнительно проверяет публичность всех DNS-ответов и доверенный TLS; служебный адрес вместо GitHub вызывает `git_restricted_host`. Успешная проверка подтверждает объявленный ref/OID на момент запроса, а подкаталог/тип объекта/содержимое остаются проверками Fetch.

## GUI выбора папки без Docker

```sh
make build
python3 tests/integration/directory_picker_process_smoke.py \
  --manager-binary bin/ctf-manager \
  --report var/publication/directory-picker-browser.json
```

Нужны Node.js и установленный в проверочной среде Playwright с Chromium. Скрипт также умеет использовать уже имеющийся runtime Codex; самостоятельно браузер и пакеты не устанавливает. Для повторного запуска укажите новый путь отчёта. Проверка запускает собственные временные executor/dashboard, создаёт Admin через stdin, открывает реальную панель без API mocks и завершает процессы/удаляет fixture. Никаких Docker-контейнеров или регистрации сервисов: Docker endpoint указывает на отсутствующий временный socket. В отчёт не записываются credentials, локальные пути, логи или screenshots.

Проверены корни, подпапки, parent, Compose-подсказка, выбор/отмена, ручной ввод, ошибки/повтор, отсутствие symlink и узкий экран. Это локальная GUI-проверка; она не заменяет Linux/CTF-приёмку регистрации и Deploy.

## Дополнительная приёмка 20 октября 2026

Текущие результаты и ограничения приведены в [матрице](progress.md). Финальные локальные Compose-образы закреплены как executor `c2f131aae98e…` и dashboard `1d0cf9d4439a…`; оба содержат бинарник с SHA-256 `225f577c2b10ac2045f054f78c8cba8f2d171a6334280ae5c34eb7003cb5ce3b`. Новые Docker сценарии создают собственные временные проекты; они не регистрируют и не переключают существующие SibirCTF.

```sh
make test-race vet frontend-check packaging-check fixtures-check
python3 tests/integration/compose_smoke.py --report tests/integration/reports/compose-smoke-2026-10-20.json
python3 tests/integration/unprepared_host_smoke.py
python3 tests/integration/journal_fault_smoke.py
python3 tests/integration/apply_efbig_linux.py
python3 tests/integration/fault_release_smoke.py --report tests/integration/reports/fault-release-smoke-2026-10-20.json
python3 tests/integration/fault_multi_component.py
python3 tests/integration/mvp_workflows_smoke.py --capture-live-sqlite
python3 tests/integration/mvp_workflows_smoke.py --pipeline-negatives-only --capture-live-sqlite --report tests/integration/reports/mvp-pipeline-negatives-smoke-2026-10-20.json
python3 tests/integration/observation_load.py --seconds 300 --lifecycle-under-load --report tests/integration/reports/observation-load-2026-10-20.json
```

`journal_fault_smoke.py` кросс-собирает Store test для реальной архитектуры daemon и запускает его на отдельном tmpfs 2 MiB без сети, capabilities и Docker socket. Действительный ENOSPC/SQLite FULL возникает при попытке завершить уже начатую mutation. После ошибки и повторного открытия проверяются неизменность операции/events/locks/recovery point, `integrity_check` и перевод в interrupted. Это не имитация `PRAGMA max_page_count` и не проверка fsync/power loss.

`apply_efbig_linux.py` запускает filesystem test в дочернем Linux-процессе с ограничением размера файла. Первый файл фактически заменяется, второй получает EFBIG. Проверяются cleanup temp, сохранность unmanaged data, отказ устаревшего manifest и компенсация по наблюдённому partial tree. `fault_multi_component.py` отдельно проверяет полный executor/Docker pipeline с EROFS, двумя target и двумя постоянными SQLite-зависимостями: failed Recover требует нового подтверждения; detail API различает версии компонентов, данные и dependency identities сохраняются.

[SQLite lock-safety report](../tests/integration/reports/README.md#report-sqlite-wal-lock-safety-2026-10-20-json) фиксирует найденный продуктовый дефект: прежнее измерение storage закрывало обычные FD активных DB/SHM в writer процессе, снимая POSIX locks. Затем другой CLI/reader мог удалить живые WAL/SHM. Новый regression на реальных Store-процессах падает на старой реализации и проходит после Linux `O_PATH|O_NOFOLLOW` / Darwin `Root.Lstat`; mount ID и symlink guards сохранены и отдельно проверены. Это не несовместимость Python SQLite. Production workflow с `--capture-live-sqlite` теперь сравнивает текущие данные отдельного Python reader с offline DB после штатного закрытия writer, проверяя linked sidecars, terminal locks и durable observations.

Флаг `--lifecycle-under-load` выполняет дополнительный этап после измерения ресурсов: генераторы логов пяти игр продолжают работать, каждая игра читает флаг и пишет/читает state, пока **только собственная тестовая панель** проходит Compose down/up. Проверяются запросы внутри интервала простоя, 10 game IDs/StartedAt, восстановление registry/IPC и отзыв старой сессии. Этот этап исключён из измеряемого CPU/RSS интервала. Образы фиксируются по immutable ID до setup и не меняются при down/up; неуспешные thresholds или cleanup дают ненулевой exit code.

[Security report](../tests/integration/reports/README.md#report-security-acceptance-2026-10-20-json) перечисляет новые race tests с реальными HTTP/WS/Unix сокетами: Viewer не доходит до privileged RPC, отзыв доступа не выпускает ожидающий приватный кадр, медленный reader не блокирует другого viewer. Log parser проверяется на управляющих символах, многобайтном UTF-8, больших frames и фильтрах. Исправлен порядок `redact → sanitize → UTF-8-safe byte cap`.

Git transport tests используют настоящий smart-HTTPS backend и клиент: auth/TLS, repo-scoped credentials, запрет redirects/alternates, HTTP503, cancel и два commits перемещаемой ветки. Временный CA/private URL доступны только package-private test runner. Публичный `Fetch` не получил обхода DNS/IP/TLS-проверок. Это не положительная приёмка приватных аккаунтов GitHub/GitLab.

Доступная среда — Linux/arm64 OrbStack, 6 CPU и 11,74 GiB RAM; desktop-клиент — Darwin/arm64. Пользователь подтвердил отсутствие отдельного Linux/amd64 стенда. Прогоны здесь не закрывают первый обязательный target, benchmark на dedicated VM 4 vCPU/8 GiB/SSD, настоящий daemon restart, registry outage на стороне daemon и fsync/power-loss series. Опорную нагрузку позднее повторяют с `--reference-host` на действительно выделенной подходящей VM. Существующий общий daemon для аварийной приёмки не перезапускается.

## Начальные fixtures

Стенд работает независимо от панели. Общий исходник — `tests/fixtures/app/app.py`,
Python standard library, HTTP и SQLite. Зависимостей PyPI нет. Базовый образ
зафиксирован как `python:3.13.7-slim-bookworm`; перед первым запуском нужен доступ
к registry либо заранее загруженный образ. Тег фиксирует версию Python, но не
гарантирует неизменность registry manifest: для отчётов релиза нужно дополнительно
сохранять фактические image ID/digest. Реальные проверки релизного pipeline
executor описаны ниже отдельно от этого начального fixture.

В профиле named volume БД выделена в отдельный контейнер: небольшой HTTP storage
service хранит SQLite на named volume. Это позволяет проверить сохранение данных
и отсутствие пересоздания зависимости при переключении приложения без скачивания
PostgreSQL и установки драйвера. Такой стенд не проверяет особенности PostgreSQL,
его backup и миграции. Последующие реальные профили ncdex и CyberBank отдельно
проверяют сохранение PostgreSQL-записей при переключении приложений; они также
не заменяют проверку backup и совместимости изменений схемы.

## Материализация проектов

Исходные каталоги `named-volume/`, `bind-mount/`, `writable-layer/` — шаблоны.
Не запускайте Compose непосредственно из них. Подготовка создаёт три независимых
проекта, у каждого свой `compose.yaml` и внутренний build context `code/`:

```sh
python3 tests/fixtures/prepare.py --destination /tmp/ctfm-fixtures-dev
```

Каталог назначения должен отсутствовать. Скрипт не перезаписывает существующие
файлы и игровые данные. Для одного профиля добавьте `--fixture bind-mount`.
Сгенерированная `.env` bind-профиля содержит UID/GID текущего пользователя,
чтобы контейнер мог писать в `data/` без root и широких прав на хосте.

Скопированный проект можно использовать как основу регистрации и клонировать в
отдельный source workspace. В управляемую карту входит `code/` и `compose.yaml`;
`data/` никогда не входит в снимки управляемых файлов. Для bind-профиля `.env` —
подтверждённая конфигурация UID/GID, изменение которой требует проверки политики.

| Профиль | Управляемые файлы | Сохраняемые данные | Обычная цель переключения | Поддерживаемость |
|---|---|---|---|---|
| `named-volume` | `compose.yaml`, `code/` | volume `<project>_database-data` → database `/data` | Только `app`; `database` остаётся работать | Поддерживаемый профиль, после подтверждения volume |
| `bind-mount` | `compose.yaml`, `code/`; `.env` как конфигурация | Каталог `data/` → app `/data` | `app`, вместе с контролируемым переключением кода | Поддерживаемый профиль после подтверждения mounts; нельзя менять активный `code/` при подготовке |
| `writable-layer` | `compose.yaml`, `code/` | `/data/state.sqlite3` внутри writable layer | Пересоздание `app` потеряет данные | Должен отклоняться при регистрации до выноса данных в подтверждённый mount |

`database` и `app` не используют `privileged`, host namespaces, Docker socket
или capabilities. Порты публикуются только на `127.0.0.1` и выделяются Docker
динамически. Хранилище БД не публикует порт на хосте.

## HTTP-контракт

Все ответы — JSON, `Cache-Control: no-store`. Доступная версия читается из
`/app/VERSION` при запросе; изменение bind-mounted VERSION видно сразу. Это
намеренно воспроизводит риск изменения активного дерева до завершения build.

| Метод и путь | Результат |
|---|---|
| `GET /health` | `200 {"status":"ok","role":"app","storage":"sqlite"}`; для named app `storage=remote`, проверяется доступность БД |
| `GET /version` | `200 {"version":"v1","role":"app"}` |
| `PUT /flags/<key>` | Тело `{"value":"CTFM_TEST_FLAG_DEMO"}`; `200 {"key":"…","value":"…"}` |
| `GET /flags/<key>` | `200` с тем же значением, `404 {"error":"not_found"}` при отсутствии |
| `PUT /state/<key>` | Аналогичный API для независимого пространства игрового состояния |
| `GET /state/<key>` | Чтение игрового состояния |
| `DELETE /flags/<key>` или `/state/<key>` | Удаление только указанной тестовой записи; `200 {"key":"…","deleted":true}` |

Ключ: 1–80 символов `A–Z a–z 0–9 _ -`; значение — строка до 2048 символов,
включая пустую. PUT требует `Content-Type: application/json`, единственное поле
`value`, тело до 4096 байт. Ошибки валидации дают `400`, размера — `413`, типа
содержимого — `415`. Недоступная БД даёт `503`, без содержимого флагов в ошибке.
Флаги передаются в JSON-теле, а не в URL или логе запросов.

## Автоматическая проверка

HTTP-проверки приложения без Docker:

```sh
python3 -m unittest discover -s tests/fixtures -p 'test_*.py'
python3 -m unittest discover -s tests/fixtures/app -p 'test_*.py'
```

Первая команда проверяет независимость проектов и отказ от перезаписи данных.
HTTP-тесты запускают временные серверы на случайных loopback-портах и проверяют:
запись/чтение и сохранение SQLite между экземплярами, разделение namespaces,
удаление конкретного ключа, remote storage, недоступность БД, VERSION и ограничения
входных данных. Для этих тестов окружение должно разрешать bind к loopback.

Полный fixture smoke на машине с доступным Docker daemon:

```sh
python3 tests/integration/fixture_smoke.py --report /tmp/ctfm-fixture-report.json
```

Скрипт:

1. Проверяет версии Docker Engine/Compose и материализует независимые проекты.
2. Проверяет Compose config: внутренние contexts и loopback-порты.
3. Собирает и запускает только эти fixtures под уникальными именами
   `ctfm-fixture-{named,bind,layer}-<run-id>`.
4. Записывает и читает уникальные тестовые флаги и состояние.
5. Пересоздаёт `app` через `--no-deps` и проверяет сохранение named/bind данных.
6. Проверяет, что named database не пересоздан при переключении приложения, затем
   отдельно пересоздаёт database и проверяет сохранность named volume.
7. Проверяет изменение VERSION в bind-коде и возвращает его в `v1`.
8. Для writable-layer подтверждает потерю записей при пересоздании. Это успешная
   отрицательная проверка стенда, а не поддержка этого профиля панелью.
9. Останавливает только созданные проекты через `compose down --remove-orphans`.

Опции: `--fixture named-volume` для одного профиля; `--keep` оставляет контейнеры
для осмотра. Произвольные Compose paths и имена проектов скрипт не принимает.
По умолчанию он не удаляет volumes, bind data, образы или временные проекты;
оставленные пути и имена volume выводятся в JSON-отчёте. Это сохраняет данные для
разбора сбоев. После серии прогонов их очищают отдельно, выбрав конкретные
тестовые ресурсы из отчёта. Глобальные prune-команды не используются.

Успешный fixture smoke подтверждает работоспособность стенда. Он не проверяет
Deploy/Rollback, авторизацию, снимки и recovery панели — соответствующие
приёмочные сценарии добавляются по этапам 1–7. Отчёт с ошибкой Docker socket,
недоступным daemon или неудачным pull/build не считается пройденным тестом.

Зафиксированный прогон 19.10.2026:
[fixture-smoke-2026-10-19.json](../tests/integration/reports/README.md#report-fixture-smoke-2026-10-19-json) — все три профиля прошли,
Docker Engine 29.8.2, Compose 5.5.0, Linux/arm64 в OrbStack. Контейнеры после
теста остановлены; named volume и bind data оставлены. Это дополнительная
разработческая среда, не подтверждение целевого профиля Linux/amd64 с systemd.

## Ручной запуск

После материализации:

```sh
docker compose -f /tmp/ctfm-fixtures-dev/named-volume/compose.yaml up --build --detach
docker compose -f /tmp/ctfm-fixtures-dev/named-volume/compose.yaml port app 8080
```

Вторая команда выводит `127.0.0.1:<случайный порт>`. Используйте его для запросов:

```sh
curl -H 'Content-Type: application/json' --data '{"value":"CTFM_TEST_FLAG_DEMO"}' \
  -X PUT http://127.0.0.1:PORT/flags/manual_demo
curl http://127.0.0.1:PORT/flags/manual_demo
```

Остановка сохраняет named volume:

```sh
docker compose -f /tmp/ctfm-fixtures-dev/named-volume/compose.yaml down
```

Не используйте `down -v`: цель стенда — проверять сохранение данных. Развёртывание
на настоящих игровых проектах smoke-скриптом не предусмотрено.

## Проверки файловых артефактов этапа 3

`internal/filesystem` и `internal/snapshots` имеют отдельные тесты сохранения
данных, целостности и опасных путей:

```sh
go test -race ./internal/filesystem ./internal/snapshots
```

Capture копирует только managed paths, учитывает literal exclusions и исключает
`.git/.hg/.svn`. Физические артефакты принадлежат executor: каталоги `0700`, файлы
`0400`; original mode/UID/GID записаны в manifest. `MaterializeBuild` восстанавливает
mode, включая executable bit, в отдельном пустом контексте без смены владельца.
Apply требует остановленных app targets и прежнего manifest без drift, заменяет
файлы через temporary file + rename + fsync и не использует recursive deletion.
Операция над всем деревом не является атомарной: executor обязан предварительно
записать намерение и recovery point и выполнить сверку после сбоя.

Текущий ограниченный профиль отвергает все symlinks, включая безопасные внутренние,
special files, hard-linked regular files и смену типа file ↔ directory. Это
временное ограничение, а не выполнение всего §11 ТЗ. Поддержка внутренних
относительных symlinks требует отдельной реализации и приёмки.

Linux проверяет namespace границу по обязательному statx mount ID; nested bind
mount на той же файловой системе тоже блокируется. Device ID остаётся частью
проверки идентичности одного inode до/после открытия, но не сравнивается между
разными объектами дерева: OverlayFS вправе возвращать разные st_dev для каталогов
и regular files одного mount. Это поведение описано в
[документации ядра Linux](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html). Ядро без mount ID не проходит проверку. Darwin нужен
для разработки и проверяет device ID; его проверки не подтверждают политику
Linux mount boundaries. Тест `TestNestedMountBoundary` автоматически использует
`/dev/shm` на Linux; переменная `CTFM_TEST_NESTED_MOUNT_ROOT` задаёт специально
подготовленный корень с nested mount в `code/`, а
`CTFM_TEST_REQUIRE_SAME_DEVICE=1` дополнительно проверяет равенство device ID.

Проверенный прогон 19.10.2026: Darwin `go test -race` прошёл; Linux/arm64 binaries
filesystem и snapshots прошли в контейнере UID 10001 с read-only root, временным
`/tmp`, отключённой сетью и удалёнными capabilities. Отдельно прошла проверка
same-device nested bind mount. Эти проверки не заменяют аварийные тесты
Deploy/Rollback через executor.


## Production executor в контейнере: bind-код и bind-данные

```sh
python3 tests/integration/container_release_smoke.py
```

Перед запуском нужен собранный `ctf-manager-executor:local`, кешированные образы
`python:3.11-slim` и `python:3.13.7-slim-bookworm`, Docker daemon и Go toolchain
с загруженными зависимостями проекта. `--executor-image` выбирает конкретный
локальный образ, `--report` — JSON-отчёт. Go используется только для небольшого
fixture helper, вызывающего реальный Vault.Revoke; helper отсутствует в образах
продукта и ограничен каталогами `/srv/ctfm-container-release-*`.

Скрипт создаёт уникальный native Linux daemon directory под `/srv`, монтирует
его по одному абсолютному пути в helper/executor/игровой контейнер и использует
production bootstrap с `development=false`. Общие `/srv` и `/` не монтируются.
Docker volume mountpoints под `/var/lib/docker` намеренно не используются как
service root: политика защищает этот системный путь. Executor запускается как
`0:10001` с read-only root, без сети, с CHOWN/DAC_OVERRIDE/FOWNER, без privileged
и host namespaces. Временный игровой app работает с UID 10001, read-only code
bind и отдельным writable bind данных.

Проверяется реальная цепочка baseline → Prepare → Build → Deploy → Rollback через
CLI typed preview/submit и Unix socket. Prepare/Build не меняют активный bind-код;
переключения сохраняют тестовый флаг, состояние и точную идентичность data bind.
Остановка и запуск executor не перезапускают игровой контейнер. Удаление только
приватного image candidate и отзыв реальной версии synthetic env-secret приводят
к отказу до stop приложения, без перезапуска app и потери флага.

Для rollback администраторский fixture wrapper отвергает отдельные Compose
`build`/`pull` команды и сохраняет фактические аргументы; успешный откат должен
использовать `up --no-build --pull never --no-deps`. Отключение сети executor и
этот guard проверяются отдельно от недоступности registry самому daemon. Сеть
Docker daemon не меняется, поэтому это не подтверждение полного сценария A06
с заблокированным registry.

Cleanup останавливает только созданный проект, удаляет собственные retention
теги и содержимое собственного временного каталога. Пустой native daemon
каталог остаётся: его parent не монтируется ради rmdir. Имена и пути записаны
в отчёт; глобальные prune не применяются. Наблюдение StartsAt чужих контейнеров
носит информационный характер: параллельные задачи могут их перезапускать,
этот smoke не выполняет над ними никаких действий.

Приёмка выявила и закрыла две ошибки контейнерного профиля: ложное отклонение
OverlayFS из-за разных st_dev каталогов/файлов и попытку Buildx сохранять свой
state в HOME=/nonexistent при read-only root. Теперь каждый Compose action
получает отдельный private DOCKER_CONFIG под executor state и удаляет его по
завершении; inherited credentials/plugin settings не используются. Обе правки
покрыты regression tests. Linux boundary tests исполнены на arm64 и amd64
(amd64 через доступную эмуляцию), включая блокирование nested mounts.

Прогоны 19.10.2026: [Linux/arm64 production container](../tests/integration/reports/README.md#report-container-release-smoke-2026-10-19-json)
и [Linux/amd64 Go executor через эмуляцию](../tests/integration/reports/README.md#report-container-release-amd64-emulated-2026-10-19-json)
прошли проверки релизного цикла и отказов; arm64 executor дополнительно
прошёл CLI storage/rotate с реальной ротацией четырёх manual snapshots до трёх.
Во втором случае Docker daemon и CLI имеют arm64: это
исполнение amd64 executor, а не приёмка всего стека на native amd64 Linux сервере.
Реальный [same-device nested bind regression](../tests/integration/reports/README.md#report-linux-mount-boundary-regression-2026-10-19-json)
также прошёл обеими архитектурами. Целевой native Linux/amd64 и сценарий недоступного
registry самому daemon остаются отдельными приёмочными проверками.


## Linux backup и maintenance

[Сохранённый Linux-прогон](../tests/integration/reports/README.md#report-linux-backup-maintenance-2026-10-19-json)
исполняет static test binaries `internal/backup` и `internal/maintenance` для
arm64 и amd64 (эмуляция) в cached Alpine: rootfs read-only, сеть отключена, Docker
socket отсутствует, capabilities удалены кроме CHOWN и DAC_OVERRIDE. Case
`TestProtectedRestorePreservesProductionUIDSeparation` фактически проходит:
executor и его БД восстановлены с UID 0, dashboard и его БД — с UID 10001,
каталоги 0700, файлы 0600. Тесты также проверяют WAL snapshot, очищенный metadata
export, encrypted full roundtrip, отсутствие старых сессий, отмену очереди,
сохранение recovery locks/tombstones и отказ unsafe/corrupt archive. Это не
проверка восстановления images или игровых БД: они находятся вне backup панели.

## Host-метрики, часовая история и нагрузка

```sh
make frontend-check
go test -race ./internal/monitoring ./internal/executor ./internal/transport ./internal/dashboard
make packaging-check
docker compose build
python3 tests/integration/compose_smoke.py --report tests/integration/reports/compose-metrics-smoke-2026-10-19.json
python3 tests/integration/observation_load.py --seconds 300
```

Парсеры procfs проверяют единицы, переполнение, сбросы счётчиков и отсутствующие
источники. Тесты истории используют управляемое время: 60-минутная граница,
721 точка, выброс устаревших наблюдений, обратный ход часов, конкурентное чтение,
лимиты памяти и размера IPC-ответа. Это проверка алгоритма хранения, а не
заявление о часовом непрерывном прогоне. Frontend-тесты проверяют разрывы,
смену container ID, отсутствующие/нулевые значения и вычисление сетевых скоростей.

`observation_load.py` создаёт отдельные пять named-volume fixture-проектов
(10 контейнеров) и production Compose-панель. Пять приложений дают суммарно
200 строк по 1024 байта с newline в секунду; пять реальных авторизованных
WebSocket-клиентов читают логи. Каждые полсекунды выполняются два запроса:
состояние executor и реальный runtime state одного сервиса по кругу. Раз в
5 секунд запрашиваются host/container history; collector работает независимо.
Скорость логов подтверждается последовательными номерами, сохранность игры —
StartedAt контейнеров и тестовыми флагами.

Суммарный CPU измеряется по cgroup usage двух контейнеров, включая их healthchecks
и накладные расходы sampling exec. RSS — VmRSS основных процессов web/executor;
игровые контейнеры, Docker/BuildKit и браузер не включены. p95 считается для
пары status+service-details, что строже одного запроса. Задание snapshot
создаётся и проверяется после интервала наблюдения. Условия, image IDs, временные
ряды и thresholds сохраняются в JSON. Короткий `--seconds 20` — preflight;
`--review-seconds 90` открывает окно для проверки UI после измерений.

Скрипт не меняет конфигурацию общего daemon и не объявляет подходящим произвольный
host. Для принятия §17.3 нужны выделенный Linux VM 4 vCPU / 8 GiB / локальный SSD
и как минимум 300 секунд измерений; CPU/RAM VM и отдельная аттестация стенда
фиксируются в отчёте. Результат на OrbStack является дополнительным свидетельством,
а не закрытием приёмки опорного стенда.

Отчёт сохраняется атомарно каждую минуту измерений и до review/cleanup. Промежуточные
`status: running` и `phase` не означают принятую проверку. Очистка должна
подтверждаться отсутствием ресурсов с точными UUID project labels и приватных
image tags; при неудачной проверке каталог daemon сохраняется для разбора.

Итоговый [нагрузочный отчёт 19.10.2026](../tests/integration/reports/README.md#report-observation-load-2026-10-19-json):
300,20 с; 171,55 MiB суммарного peak RSS; 0,0422 ядра average CPU; p95 пары
status+runtime details — 26,45 мс; submit — 1,50 мс. Все пять флагов и StartedAt
сохранены, snapshot успешен, очистка ресурсов перепроверена независимо. Прогон
выполнен на общей VM 6 CPU / 11,74 GiB и не закрывает reference acceptance.
В JSON отдельно отмечены версия harness при старте и дополнительная проверка
строгого интервала ≥300 с и отсутствия ресурсов после правок проверки cleanup.

## Аварии релизного pipeline

```sh
python3 tests/integration/fault_release_smoke.py --help
```

Внешний fixture Docker Unix proxy и Compose wrapper удерживают операцию до/после
реальных изменяющих запросов. Harness завершает production executor через SIGKILL
на выбранной границе, проверяет persisted stage/state/locks, отсутствие повторного
переключения при retry и затем выполняет явный Recover. Проверяются также потеря
ответа Submit, потеря настоящего ответа Docker Stop, отказ API и исчезновение
компонента. Production test hooks для этих испытаний не добавляются; общий Docker
daemon не перезапускается. Полный перечень выполненных границ и ограничения
приведены в сохранённом отчёте и [матрице приёмки](progress.md).

## Веб-регистрация и HTTPS Git (ТЗ v2.4)

После `docker compose build dashboard executor` выполните:

```sh
python3 tests/integration/web_registration_git_smoke.py
```

[Итоговый отчёт](../tests/integration/reports/README.md#report-web-registration-git-smoke-2026-10-19-json) проверяет реальные HTTP/Unix/Docker вызовы на отдельном временном native volume. Сервис добавляется по пути, заявка подтверждается через панель API без CLI, baseline/workspace создаются автоматически; повтор подтверждения не дублирует регистрацию. Проверяются digest, отказ вне корней/без CSRF, запрет Defender/Viewer на регистрацию и настройку источника, право Defender просмотреть fetch и запрет Viewer.

Положительное получение использует публичный GitHub SibirCTF/ncdex, точный commit `435b7108d3b8c2693467a9e4be8a5c71b0936d64`. Кандидат содержит управляемый `LICENSE`, затем собирается image-only релиз с той же Git provenance; фактические app/database используют bundled fixture image. Это не запуск upstream сервиса. Неверный ref сохраняет прежний кандидат, container IDs/StartedAt и записанный тестовый флаг неизменны. Изолированный стенд и его tags/volumes удаляются. GitLab, настоящие private credentials, перемещение ветки, timeout/offline и полный Git Deploy/Rollback не подтверждены этим smoke.

[Linux Git isolation proof](../tests/integration/reports/README.md#report-linux-git-isolation-2026-10-19-json) отдельно выполняет sourcegit tests в Linux/arm64 runtime с production capabilities. Он подтверждает сброс UID/GID, отсутствие токена в argv/файлах, запрет ambient config/filters, LFS/blob limits и безопасное завершение oversized-blob процесса. Во время проверки обнаружена и исправлена необходимость `KILL` для управления дочерним процессом другого UID; один лишь UID 0 при `cap_drop: ALL` такого права не даёт.

Unit/race tests дополнительно покрывают concurrent approval, неполную инициализацию source workspace, сбои квоты/частичной staging-копии, crash gap до rename/marker, сохранение авторских правок и точное равенство provenance в SQLite и snapshot artifact. Общая матрица MVP и native Linux/amd64 приёмка остаются открытыми по [progress.md](progress.md).

В ранней попытке браузерная приёмка не состоялась из-за недоступного CUA/iab и зависшего выбора native Firefox. [Исторический отчёт](../tests/integration/reports/README.md#report-web-registration-browser-2026-10-19-json) сохранён; последующий успешный интерактивный прогон описан ниже.

## BioGuard: настоящий Git → Build → Deploy → Rollback через браузер

[Отчёт полного цикла](../tests/integration/reports/README.md#report-sibir-bioguard-web-cycle-2026-10-19-json) фиксирует запуск настоящего Django-приложения SibirCTF на Linux/arm64 OrbStack с production dashboard/executor. Регистрация, review/approve, подключение Git URL и все четыре операции выполнены кнопками панели. Скрипт `observe_panel.py` только читает API после входа; `sibir_bioguard_cycle.py` подготавливает отдельный Compose-проект до регистрации и проверяет приложение по HTTP. Эти скрипты не регистрируют сервис и не отправляют операции executor.

Подготовленный профиль `ctfm-preview-sibir-bioguard` собирает неизменённый upstream Dockerfile из `vuln-service`. До регистрации SQLite вынесена в named volume `/data`, настройки заданы отдельным frozen read-only bind вне Git-кода. Добавлены loopback-публикация случайного порта, Docker healthcheck, лимиты и bounded logs; runtime entrypoint выполняет `migrate`, затем `runserver --noreload`. Исходный upstream Compose с SQLite в writable layer для безопасного пересоздания по-прежнему не подходит.

Последовательность воспроизведения на отдельном подготовленном стенде:

1. Добавить через мастер каталог проекта, оставить управляемым только `vuln-service`, классифицировать SQLite volume как значимые данные, принять потерю временного writable layer. Runtime Compose и внешний settings bind остаются вне управляемого Git-кода.
2. Подключить `https://github.com/SibirCTF/2025-cybersibir-service-BioGuard.git`, ref `0d5dffae3460823715a266d5674d2110837c4bea`, пустой подкаталог; просмотреть immutable заявку и подтвердить Admin. Дождаться automatic baseline/workspace.
3. Через настоящий `/register` создать синтетического пациента, затем свежим `/login` проверить diagnosis на `/profile`. Helper хранит пароль только в приватном файле `0600`, который не включается в отчёт.
4. Нажать «Получить из Git», подтвердить preview; затем «Собрать» и подтвердить сборку. Снять runtime/probe evidence: baseline container ID, image, StartedAt, код и данные должны остаться прежними.
5. В «Применить» явно выбрать **новый Git-релиз**, просмотреть изменения и подтвердить совместимость данных. После успеха проверить новый exact image, исчезновение baseline-надписи и свежий вход того же пациента.
6. В «Откатить» выбрать imported baseline, просмотреть план и подтвердить совместимость данных. Проверить возврат точного baseline image и шаблона при сохранении identity volume и diagnosis.

Выполненный прогон: Fetch 1,185 с, Build 4,899 с, Deploy 17,163 с, Rollback 17,069 с. Это сборка настоящего исходного кода с доступным Docker cache; времена не являются cold-cache benchmark. Named volume, его mountpoint/CreatedAt, внешний bind и хеши frozen Compose/settings/Dockerfile не менялись. При Rollback новых Build/Fetch и релизов не появилось. Оба переключения создали recovery point, записали `succeeded` и освободили locks. Исходный демонстрационный проект сохранил свои IDs/StartedAt.

Baseline локально помечен надписью `CTFM imported local baseline`; точный Git-кандидат её удаляет. Это проверка реального исходного кода и Docker-сборки с возвратом на импортированный релиз, а не двух различных upstream commit или миграции схемы. [Сравнение manifests](../tests/integration/reports/README.md#report-sibir-bioguard-manifest-diff-2026-10-19-json) подтверждает все 36 upstream blobs: 45 общих записей меняют GID `0→10001`, из них у одного HTML также меняется содержимое; две записи tracked upstream cache добавляются после пропуска при импорте baseline. Поэтому UI показывает 47 изменений.

Docker healthcheck и отдельные HTTP-пробы signup/login/profile прошли. Executor readiness/functional URL-пробы в этом профиле не настроены (`checks_not_configured`), checker/exploit организаторов не запускались. На конец этого первого прогона healthy сервис оставлен на baseline по адресу `http://127.0.0.1:32841`, Git-релиз сохранён. Во время последующих четырёх циклов у BioGuard отдельно наблюдались Build и Rollback на ранее собранный Git-релиз: текущий адрес стал `http://127.0.0.1:32842`, прежний diagnosis повторно прочитан; эти операции отделены в сводном отчёте и не отменялись. Динамический порт меняется при recreation. GitLab/private credentials, moving ref, timeout/offline и native Linux/amd64 остаются отдельными испытаниями. Прогоны остальных четырёх сервисов описаны в следующем разделе.

Снимки экрана регистрации, Git и успешных операций сохранены локально; [публичное описание](../tests/integration/reports/README.md#report-screenshots-sibir-bioguard-jpg) не содержит этих вложений. `report_sibir_bioguard_cycle.py` повторно сверяет локальные `var/preview/sibir-bioguard-{baseline,built,deployed,rollback}-{panel,runtime,probe}.json` и собирает отчёт без patient credentials и cookie jar. Новый сгенерированный отчёт остаётся локальным: перед отдельной публикацией требуется проверить его содержимое.

## Остальные четыре SibirCTF: проверки через браузер

Полные браузерные циклы [ncdex](../tests/integration/reports/README.md#report-sibir-ncdex-web-cycle-2026-10-19-json), [CyberBank](../tests/integration/reports/README.md#report-sibir-bank-web-cycle-2026-10-19-json), [neLi234](../tests/integration/reports/README.md#report-sibir-neli234-web-cycle-2026-10-19-json) и [EyeSee](../tests/integration/reports/README.md#report-sibir-eyesee-web-cycle-2026-10-19-json) завершены **passed**. Вместе с BioGuard проверены все пять адаптированных сервисов. [Сводный отчёт четырёх новых прогонов](../tests/integration/reports/README.md#report-sibir-four-web-cycles-2026-10-19-json) связывает регистрацию, реальные Git/build артефакты, runtime/data evidence и снимки браузера.

Каждый проект имеет собственный `ctfm.runtime.yaml` и native daemon directory под `/srv/ctf-manager-preview/services`, подготовленные до веб-регистрации. Код управляется через `vuln-service`, а runtime Compose, реальные секреты и игровые хранилища остаются вне Git candidate. Фактический workflow: браузерный мастер → Admin review/approve → Git Fetch → Build → выбор нового Git-релиза в Deploy → проверка данных → Rollback к imported baseline → повторная проверка. Кнопки подтверждения совместимости данных используются в панели. `observe_panel.py` после аутентификации делает только GET; `sibir_*_cycle.py` создают первоначальный стенд и выполняют легитимные application probes, без отправки service operations.

| Сервис | Сборка и targets | Проба сохранения данных |
|---|---|---|
| ncdex | Unchanged upstream Crystal Dockerfile, только `app`; PostgreSQL продолжает работать | Новый HTTP cookie jar и password login, тот же ID и содержимое игровой записи в PostgreSQL |
| CyberBank | Оба upstream Dockerfile API и React/nginx; API source неизменён и его image переиспользован, frontend image сменился | Свежий login, тот же пользователь/продукт/content/комментарий, точный SHA-256 generated PNG в отдельном volume |
| neLi234 | Upstream C++ controller пересобирается на arm64; только `controller` target, opaque amd64 neurolink dependency исключена | TCP login после Rollback читает исходные и новые thoughts из SQLite volume и concepts/solutions из RAM того же neurolink; SHA-256 расширенного SQLite-файла сохранён, restart durability aux не проверяется |
| EyeSee | Upstream Dockerfile упаковывает supplied amd64 executable, выполняемый через эмуляцию; MinIO — отдельная dependency | gRPC prescription и patient relation, сохранённые в MinIO named volume; повторный CheckPrescription/GetPrescriptionIDs |

Подготовка профилей явно учла ограничения нормализатора: `shm_size: 64m` для всех компонентов, project-local `secrets/*.env` у CyberBank, удаление runtime `platform` и controller `tmpfs` у neLi234 до регистрации. Архитектуры выбирались при начальной сборке; opaque dependency не пересоздавалась при адаптации уже работающего профиля и переключениях controller. У ncdex исправлен upstream DSN, сохранены схема/seed без исходного 16 GiB tuning. Для EyeSee MinIO собран из официального tag `RELEASE.2025-02-28T09-55-16Z` (`8c2c92f7afdc8386b000c0cb57ecec2ee1f5bcb0`) после отказа исторического registry image и HTTP 410 binary archive; это отдельная storage adaptation, а не сборка приложения EyeSee из Go source.

При инспекции нельзя оставлять автоматические исключения только из-за имени каталога: `cyberBank/src/db` — восемь TypeScript-файлов, `front/.nginx` — необходимый build input. В CyberBank сохранено единственное исключение `.env`; [immutable comparison](../tests/integration/reports/README.md#report-sibir-bank-manifest-diff-2026-10-19-json) проверяет все 79 выбранных upstream blobs. Действительные БД/секреты/generated images не входят в code manifest. Аналогичные сравнения и probe hashes сохраняются для каждого профиля.

Upstream SQLite amalgamation neLi234 (9 235 994 байта) и поставляемый ELF EyeSee (14 008 504 байта) потребовали поднять `MaxFileBytes` Git source с 8 до 16 MiB. Непрозрачный Go binary neLi234 размером около 6,36 MB причиной отказа не был. Общие `MaxTreeBytes = 32 MiB` и `MaxRepositoryBytes = 64 MiB` сохранены. [Отдельный прогон](../tests/integration/reports/README.md#report-git-bundled-source-limits-2026-10-19-json) подтвердил race tests, положительный export точного 13 MiB blob, отказ blob >16 MiB и суммарного дерева 33 MiB, а также Linux isolation tests в обновлённом executor runtime. Циклы ncdex/CyberBank завершились на исходном executor image `20b24a…`; последующие Git-повторы идут на `04656c…`, переход фиксируется в отчётах, без переноса старых результатов на новый образ.

У neLi234 первая Fetch-операция корректно завершилась отказом по прежнему лимиту 8 MiB, сохранив активный baseline и игровые данные. После исправления выполнен успешный повтор; первоначальный отказ остаётся в общем журнале. Поэтому итог полного цикла не означает успех каждой исторической попытки Fetch. Под новым Git-релизом дополнительно созданы новые SQLite/RAM-записи: Rollback сохранил как исходные, так и появившиеся после Deploy данные, точный SHA-256 расширенного SQLite-файла и container ID/StartedAt neurolink.

Во всех сценариях baseline помечен локальной контрольной меткой, точный upstream Git commit её удаляет, а Rollback возвращает. Метка EyeSee — Docker LABEL, поэтому его image Build не доказывает повторную компиляцию Go-приложения. Остальные метки видны в HTML/TCP. Тест не переключается между двумя upstream commits и не меняет схему игровых БД. Пробы отделены от panel functional checker и organizer checker; private GitLab, moving ref, registry outage и native Linux/amd64 остаются открытыми проверками по [матрице](progress.md).


### Смена Compose

`python3 tests/integration/release_smoke.py --config var/executor.dev.json --compose-revision` проверяет подготовку без остановки, смену лимитов, переход с локального на внешний порт и обратный откат. Сценарий также проверяет отказ при занятых портах и автоматический возврат после отказа функциональной проверки. Он создаёт отдельный синтетический проект, записывает тестовое значение в его БД и проверяет его после переключений.
