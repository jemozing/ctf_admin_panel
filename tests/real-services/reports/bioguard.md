# BioGuard — исходный Compose и проверенный локальный профиль

Источник: [SibirCTF/2025-cybersibir-service-BioGuard](https://github.com/SibirCTF/2025-cybersibir-service-BioGuard/tree/0d5dffae3460823715a266d5674d2110837c4bea), commit `0d5dffae3460823715a266d5674d2110837c4bea`, LICENSE MIT. Проверены Compose, Dockerfile, Django settings, models, urls и views.

## Исходный профиль: только статическая совместимость

Linux active root статического fixture: `/srv/ctfm/real-services/tests/fixtures/vendor/2025-cybersibir-service-BioGuard/vuln-service`.

Единственный компонент `web`: Django на container 4444, host `127.0.0.1:27444`. Upstream фиксирует `container_name: bioguard`; override сбрасывает имя, чтобы отдельный project `ctfm-real-bioguard` не конфликтовал с другими экземплярами. Все source data settings сохранены.

`health_corp/settings.py` задаёт SQLite `BASE_DIR / db.sqlite3`, WORKDIR — `/app`. Compose mounts отсутствуют, Dockerfile не задаёт VOLUME: игровая БД `/app/db.sqlite3` находится в записываемом слое контейнера. Recreation для deploy/rollback запрещён. Сервис может быть зарегистрирован для просмотра и инвентаризации, но пометка mount-политики «сохранить» не решает отсутствие внешнего хранилища.

Управляемые пути: `Dockerfile`, `requirements.txt`, `manage.py`, `BioGuard/`, `accounts/`, `health_corp/`; Compose отдельно. `/app/db.sqlite3` и возможные journal/WAL/shm рядом с ней исключаются из code snapshot. Копия каталога с работающей SQLite не считается согласованной резервной копией данных.

Dockerfile выполняет `makemigrations` и `migrate` во время build, а `COPY . /app` потенциально захватывает локально появившуюся БД, если не задано исключение. Без отдельного изменения layout новый build принесёт собственную начальную БД, а recreation удалит текущую. Для последующего положительного сценария требуется явное вынесение SQLite в отдельный data directory/volume, политика миграций и согласованное перенесение данных; данный fixture этого автоматически не делает.

Локальная базовая проба: HTTP GET `/`; функциональная — register → login → запись/чтение синтетических данных через documented Django views. Успешная root page не подтверждает сохранность флагов. Python checker и exploits не запускаются.

База build: `python:3.13-slim`, Django `~=5.1.6`; resolver и пакеты не закреплены в immutable image. Секрет Django встроен в upstream settings и используется только как публичный fixture source, не как секрет панели.

Pin/hash verification и `compose config` исходного статического fixture прошли; порты только loopback, restart=no. Этот исходный профиль не запускался: runtime status `not_run`; registration mode inventory-only, recreation blocked. Следующая проверка использует отдельный адаптированный профиль и не меняет этот вывод об upstream data layout.

## Адаптированный профиль: браузерный цикл Git Deploy и Rollback

19 октября 2026 года реальное Django-приложение запущено в Docker Engine Linux/arm64 внутри OrbStack. Проект `ctfm-preview-sibir-bioguard`, каталог `/srv/ctf-manager-preview/services/sibir-bioguard`, отдельный Compose `ctfm.runtime.yaml`. Контейнер `web` зарегистрирован через браузерный мастер панели, включая подтверждение роли, update target, управляемого пути `vuln-service` и data policy. Локальные `propose`/`approve` не использовались.

Профиль подготовлен до регистрации и затем сохранён как неизменяемые runtime inputs:

- Upstream Dockerfile собирает `./vuln-service`; приложение и зависимости действительно исполняются, fixture-образ не подменяет BioGuard.
- SQLite размещена в именованном volume `ctfm-preview-sibir-bioguard_sqlite-data` по `/data/db.sqlite3`.
- Отдельный `ctfm_settings.py` импортирует `health_corp.settings` и меняет только `DATABASES`. Он подключён readonly bind из `/srv/ctf-manager-preview/services/sibir-bioguard-runtime-config` по `/runtime-config`, вне дерева управляемых исходников.
- `DJANGO_SETTINGS_MODULE=ctfm_settings`, `PYTHONPATH=/runtime-config:/app`, фиксированный entrypoint выполняет `python manage.py migrate --noinput` перед `runserver 0.0.0.0:4444 --noreload`. Это декларация совместимой схемы именно для выбранных baseline и кандидата; произвольные миграции и откат схемы этим не проверены.
- HTTP опубликован только на динамическом loopback-порту: baseline `http://127.0.0.1:32839`, после Deploy `http://127.0.0.1:32840`, после Rollback `http://127.0.0.1:32841`. Смена порта при recreation ожидаема для такого профиля. Настроены Docker healthcheck, лимиты 1 CPU / 512 MiB / 128 PID и ротация container logs.
- Writable layer отмечен как временный; игровые данные и runtime settings сохраняются при recreation.

Через вкладку Git подключён `https://github.com/SibirCTF/2025-cybersibir-service-BioGuard.git` без токена, ref — точный commit `0d5dffae3460823715a266d5674d2110837c4bea`, подкаталог пустой. Браузерные операции Git Fetch, Build, Deploy и Rollback завершились `succeeded`. Само создание исходного тестового проекта и первичная сборка baseline выполнены helper до регистрации; панель импортирует существующий Compose-проект.

Для наблюдаемого переключения импортированный локальный baseline содержит HTML-маркер `<p id="ctfm-baseline-marker">CTFM imported local baseline</p>` в `BioGuard/templates/BioGuard/index.html`. Git-кандидат не исправлялся и точно воспроизводит upstream commit. После Deploy локальный маркер отсутствовал на диске и в HTTP-ответе; Rollback восстановил его в обоих местах. Это не тест перехода между двумя разными upstream commits.

[Immutable manifest comparison](../../integration/reports/sibir-bioguard-manifest-diff-2026-10-19.json) отдельно подтверждает все 36 upstream файлов кандидата по SHA-256, размеру и режиму, без лишних файлов. Diff включает 45 изменённых записей: 44 только по метаданным, `index.html` также по содержимому; GID общих записей меняется `0 → 10001`. Ещё добавлены отслеживаемый upstream `BioGuard/migrations/__pycache__/__init__.cpython-313.pyc` и его каталог, исключённые helper при подготовке baseline. Поэтому diff не ограничен единственным путём.

Функциональная проба через HTTP создала синтетического пациента с маркером в `diagnosis`, затем выполняла новый вход и проверяла `/profile`. После Git Fetch и Build сохранены прежние container ID/StartedAt, baseline-маркер и данные пациента. Deploy и Rollback создали новые контейнеры, сохранив имя, mountpoint и время создания SQLite volume; после каждого шага новый вход успешно читал прежний diagnosis. Compose и внешний settings bind сохранили исходные SHA-256.

Deploy применил image `sha256:c5ec894fa1a34ae7eda3cf098f4ceda9dd7e0b5f0620ed850a257aa1944855c0`. Rollback (`op-ce3a91884e782f128debbd16eeeb2cc6`) восстановил точный исходный image `sha256:970d137d59fc2ec780f888200968be46c952fbc27c2201c2ed7a730dcb133657` и current release `rel-a6c022492271c10e5e564e79384f11cd`. Финальный контейнер running/healthy. [Итоговый отчёт](../../integration/reports/sibir-bioguard-web-cycle-2026-10-19.json) содержит журнал операций, проверки данных и сравнение runtime до и после переключений.

Область результата: один реальный сервис, публичный GitHub HTTPS, Linux/arm64 OrbStack. Upstream checker, exploits, Linux/amd64, GitLab, private credentials, новая удалённая версия и несовместимые миграции не проверялись. Остальные четыре сервиса SibirCTF остаются без runtime-проверки.
