# NightCity Data Exchange — реальный цикл через панель

Источник: [SibirCTF/2025-cybersibir-service-ncdex](https://github.com/SibirCTF/2025-cybersibir-service-ncdex/tree/435b7108d3b8c2693467a9e4be8a5c71b0936d64), commit `435b7108d3b8c2693467a9e4be8a5c71b0936d64`, LICENSE MIT.

19.10.2026 сервис зарегистрирован через браузер по пути, Git URL подключён в мастере. Через панель выполнены Fetch → Build → Deploy → Rollback. Все пять durable operations, включая автоматический baseline snapshot, завершились `succeeded`. Полный публичный [отчёт с проверяемыми исходными данными](../../integration/reports/sibir-ncdex-web-cycle-2026-10-19.json) содержит operation/release/snapshot ID, длительности, HTTP-пробы, runtime identity, хэши файлов и сравнение manifest. Среда — OrbStack Linux/arm64; использован явно адаптированный профиль.

## Профиль запуска и данные

Проект: `ctfm-preview-sibir-ncdex`. Рабочий каталог: `/srv/ctf-manager-preview/services/sibir-ncdex`; локальный Compose: `ctfm.runtime.yaml`. Managed code — весь `vuln-service`, без исключений; Git subdirectory пустой. Приложение собирается исходным upstream Dockerfile с Crystal/Kemal и реальными зависимостями из `shard.lock`.

| Компонент | Роль и вход | Сохранение данных и настройки |
|---|---|---|
| `app` | Application, единственный update target; HTTP 7331, случайный host port только на `127.0.0.1` | Frozen read-only bind `/srv/ctf-manager-preview/services/sibir-ncdex-runtime-config/app` → `/home/appuser/config`; writable layer временный |
| `db` | PostgreSQL 17.4, database, исключён из update targets; host port отсутствует | Named volume `ctfm-preview-sibir-ncdex_postgres-data` → `/var/lib/postgresql/data`; отдельный frozen read-only init bind |

Upstream DSN `localhost:7432` несовместим с контейнерной сетью. Локальный frozen config явно задаёт `db:5432` и отдельный сгенерированный пароль. Он находится снаружи managed Git-кода. Значимые mounts сохраняются при обоих переключениях; snapshot файлов не содержит PostgreSQL data volume. Исходный `src/db/migrations/init.sql` остаётся частью управляемого кода, а живой init bind использует отдельную замороженную копию.

Из init SQL исключён только блок upstream `ALTER SYSTEM` с настройками на 16 GiB; схема, extension и начальный Exchange Account после разделителя сохранены без изменений. Для локального PostgreSQL заданы ограниченные command settings. App/db ограничены 512 MiB, 1 CPU, 128 PID; логи ротируются. До регистрации обеим службам явно задано поддерживаемое `shm_size:64m`. Подготовка проверила отсутствие регистрации, пересоздала только собственный проект без сборки и подтвердила сохранение прежнего volume и HTTP-записи. Хронология before/after включена в отчёт отдельно от baseline принятого сервиса.

## Полученный результат

| Действие через панель | Результат | Время |
|---|---|---|
| Автоматический baseline snapshot | `succeeded`, импортирован текущий образ и код | 0.162 с |
| Fetch exact Git commit | `succeeded`, candidate `snap-c93567c88cdc460c70a58123afb38071` | 1.211 с |
| Build | `succeeded`, настоящая исходная Crystal release/static сборка | 60.420 с |
| Deploy | `succeeded`, активен Git release `rel-810bdd671a5e020f612717919eeed543` | 6.404 с |
| Rollback | `succeeded`, активен baseline `rel-fbbf3b8f3e3c85b16e9583e2dd751936` | 6.526 с |

Для наблюдаемого переключения импортированный локальный baseline содержал безвредную HTML-надпись в `src/views/home.ecr`. Точный Git candidate удаляет её. Все 54 регулярных файла после Deploy совпали по SHA256 с Git blobs указанного commit. В 69 manifest entries отсутствуют добавления и удаления; 68 изменений касаются только GID `0→10001`, ещё одно затрагивает GID и содержимое/размер `home.ecr` (`1903→1837` байт). UID и mode не изменились. Метаданные отражены отдельно от изменения содержимого.

Fetch и Build сохранили активные контейнеры, их StartedAt, текущий образ и активный код. Deploy использовал новый образ `sha256:b01381cf975f8133d5be2f344a730523c9b089bbda0d7a8206151f046f19733d`, надпись исчезла. Rollback вернул точный исходный образ `sha256:9d743c599f76c63e74443e05fc6613009fcbe48bc00aec0f189987a0f9c79de6`, надпись и все 54 файла baseline. Дополнительное чтение `lstat` и содержимого подтвердило точное восстановление всех 69 entries, включая UID/GID/mode. Новых Fetch/Build operations во время Rollback не появилось.

Сохранность данных проверена штатными HTTP-действиями: регистрация уникального пользователя, создание собственного предложения и чтение его title/description/exploit владельцем. После Build, Deploy и Rollback использовались новый cookie jar и повторный парольный вход. Payload записи №1 сохранился, SHA256 `83649ccb3865847c2d091b2dc9902287bab695114252f5e269e31bbcb1cda2c2`. DB container ID `103f15f075800da47c54897bd5efacca4e3466823b2252034ad387bab3940a0c`, StartedAt `2026-10-19T15:13:56.365344146Z`, образ и mounts не изменились в принятом цикле. Имя, mountpoint и CreatedAt volume, frozen config/init и локальный Compose также сохранились. Пароли и содержимое игровой записи в публичный отчёт не включены.

Первоначальная тестовая запись использовала допускаемый SQL тип `other`, однако upstream HTML rendering для него возвращает `KeyError`. Исправлено только значение типа собственной записи на `rce` через обычный authenticated HTTP update; исходный код не менялся. Подготовительная коррекция явно записана в отчёте.

После Rollback приложение и БД оставлены healthy. Зафиксированный конечный адрес приложения — `http://127.0.0.1:32850`; при последующем пересоздании app динамический порт может измениться. Helper `tests/integration/sibir_ncdex_cycle.py` определяет текущий порт через Docker inspect; он не регистрирует сервис и не отправляет операции панели.

## Границы проверки

Проверены импортированный baseline и один точный upstream commit, совместимые с одной схемой БД. Два разных upstream commit, миграции схемы и откат игровых данных не проверялись. Docker healthchecks и внешняя HTTP-проба прошли; встроенные panel readiness/local_functional checks не настроены, события Deploy/Rollback содержат `checks_not_configured`, organizer external checker остаётся `unknown`. Ruby checker и exploit scripts не запускались. Native Linux/amd64, GitLab, приватные credentials, перемещённый ref и Rollback с блокировкой сети требуют отдельных прогонов. Этот локальный результат заменяет прежний `not_run` только для описанного профиля; исторический статический override `tests/real-services/compose/ncdex.yaml` по-прежнему не исправляет upstream DSN.
