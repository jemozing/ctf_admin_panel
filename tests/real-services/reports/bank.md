# CyberBank — совместимость и реальный цикл обновления

Источник: [SibirCTF/2025-cybersibir-service-bank](https://github.com/SibirCTF/2025-cybersibir-service-bank/tree/4a7d4eafb2e8030aa230316e3f191908a2b0437a), commit `4a7d4eafb2e8030aa230316e3f191908a2b0437a`, корневой LICENSE MIT; package.json API отдельно указывает ISC. Vendor сохраняет оба исходных уведомления. Проверены Compose, оба Dockerfile, startup, TypeORM-конфигурация, генератор изображений и nginx config.

Linux active root: `/srv/ctfm/real-services/tests/fixtures/vendor/2025-cybersibir-service-bank/vuln-service`.

| Компонент | Роль и вход | Mounts и данные | Политика |
|---|---|---|---|
| `cyber-bank-postgres` | PostgreSQL 5432; host `127.0.0.1:27338` | named `postgres` → `/var/lib/postgresql/data` | Не пересоздавать при патче API/frontend |
| `cyber-bank-api` | Node/TypeScript HTTP+WS 37773, внутренний | `./cyberBank` → `/app` rw; anonymous `/app/node_modules`; anonymous `/app/build` | До классификации mixed data inventory-only |
| `cyber-bank-front` | nginx/React HTTP 1337; host `127.0.0.1:27337` | rw binds `front/src`, `public`, `package.json`, `package-lock.json` | Требуется отдельное переключение активных bind trees |

Важный случай: `/app/build` — не только скомпилированный код. `cyberBank/src/imageGen.ts` сохраняет игровые изображения в `/app/build/static/images`. Путь находится в anonymous volume. Его ID нужно закрепить и сохранить при recreation; нельзя очищать volume как build cache, включать данные в snapshot кода или заменять пустым volume нового релиза.

Управляемые пути перечислены в `service-maps.json`: исходники API и frontend, Dockerfile, package manifests, run.sh и nginx config. `.env` — отдельная версия секретов, не обычный код; для config используются публичные synthetic credentials из `tests/real-services/bank.env`. Реальные env и generated images не входят в release. Управляемые bind mounts нельзя изменять в активном дереве при подготовке кандидата.

`cyberBank/run.sh` при каждом старте выполняет `typeormig migration:run`. Поэтому откат образа не гарантирует совместимость прежней версии со схемой; миграционная политика должна быть подтверждена до deploy. Изображение `postgres` не имеет версии: фактический PGDATA и image-declared mounts зависят от загруженного образа и требуют inspect. Наличие Compose mount `/var/lib/postgresql/data` само по себе не подтверждает, что текущая версия PostgreSQL пишет именно туда.

Базовая локальная проверка frontend: HTTP GET `/`. Она не проверяет API и БД. Дальнейшая функциональная проба должна регистрировать отдельного синтетического пользователя и выполнять API put/get продукта через `/api`; API controllers и данные проверяются отдельно от внешнего checker. `pg_isready` в Compose относится только к PostgreSQL.

Сборка включает Node22/npm, React и nginx; front bind paths `/app/...` относятся к dev layout и не совпадают с production root `/usr/share/nginx/html`, что тоже требует отдельной проверки при запуске. Snapshot источников не становится автоматически production frontend release. Не запускались jury/exploits/checkers.

Pin/hash verification и `compose config` прошли; проект `ctfm-real-bank`, wildcard ports полностью заменены loopback. Source/data/migrations в этом статическом этапе не изменялись. Исходный upstream Compose на этом этапе не запускался; ниже приведён отдельный реальный прогон с явно адаптированным runtime-профилем.

## Проверенный прогон через панель — 19.10.2026

Статус адаптированного профиля: **passed**. На OrbStack Linux/arm64 через настоящий браузер выполнены поиск проекта по пути, классификация, подтверждение immutable proposal, подключение публичного Git URL, Fetch, Build, Deploy и Rollback. Helpers готовят исходный отдельный проект и читают результаты; регистрацию и операции релизов они не отправляют. Доказательства: [полный валидируемый отчёт](../../integration/reports/sibir-bank-web-cycle-2026-10-19.json), [сравнение immutable manifest с Git](../../integration/reports/sibir-bank-manifest-diff-2026-10-19.json).

Проект `ctfm-preview-sibir-bank` находится в `/srv/ctf-manager-preview/services/sibir-bank`; выбранный Compose — `ctfm.runtime.yaml`. Оба application target, `cyber-bank-api` и `cyber-bank-front`, собираются неизменёнными upstream Dockerfile. PostgreSQL `cyber-bank-postgres` исключён из целей пересоздания. Активных bind mounts исходников нет. PostgreSQL закреплён на `17-alpine`, данные находятся в named volume `ctfm-preview-sibir-bank_postgres-data`. Только генерируемые и исходные изображения `/app/build/static/images` находятся в отдельном `ctfm-preview-sibir-bank_generated-images`; скомпилированный код и зависимости остаются в образе/слое приложения. Все компоненты имеют явный `shm_size: 64m`, ограничения ресурсов и ротацию логов. Frontend публикуется на случайном loopback-порту; API и БД не публикуют порты хоста.

Управляемый путь — `vuln-service`, единственное исключение — `.env`. Настоящие приватные env inputs лежат в project-local `secrets/api.env` и `secrets/postgres.env`, вне управляемого Git-дерева; каталог `secrets/` исключён из регистрации кода. Автоматические исключения для `cyberBank/src/db` и `front/.nginx` при проверке формы сняты: первое содержит восемь TypeScript-файлов приложения/миграций, второе требуется frontend Dockerfile. Immutable Git candidate содержит ровно все 79 выбранных upstream blobs с совпадающими SHA-256, размерами и mode, включая эти девять критичных файлов и публичный `.gitignore`. Исключённый upstream `.env` не входит ни в один app build context.

Git URL: `https://github.com/SibirCTF/2025-cybersibir-service-bank.git`, точный commit `4a7d4eafb2e8030aa230316e3f191908a2b0437a`, subdirectory пустой. Импортированный local baseline содержит явно добавленную видимую HTML-метку в `front/public/index.html`; Fetch получает точный upstream без неё. Это проверка перехода от изменённого локального baseline к pinned Git, а не двух upstream revisions. Manifest обоих снимков содержит 98 entries: один content diff удаляет метку, остальные 97 изменений касаются метаданных, главным образом GID `0 → 10001`.

| Проверка | Результат |
|---|---|
| Регистрация, Fetch и Build | Успешно; активные контейнеры, StartedAt, код, данные и volume остались прежними |
| Настоящая сборка API и React/nginx | Успешно; API использовал кэш с тем же image ID, frontend получил новый образ |
| Deploy Git-релиза `rel-36d60c85eba8509e75e0fd8c94e591f5` | Применён собранный frontend image `sha256:59df56a512c847c4b35209ca17974b065fff61ffe2a0bc1586475da4c864ccdd`; метка исчезла |
| Rollback к `rel-dd340c47b28ba091bfc245efb808df23` | Восстановлены точные baseline image IDs и исходный HTML с меткой; новых Build/Fetch не было |
| PostgreSQL | Container ID, image ID и StartedAt не изменились при Deploy/Rollback |
| Игровые данные | Свежий HTTP login после каждого переключения читает того же пользователя, продукт, content и комментарий; generated PNG совпадает байт в байт |
| Хранилища и конфигурация | Обе named volume сохранили имя, mountpoint и CreatedAt; Compose, приватные env inputs и Dockerfile сохранили hashes |

Проверочная запись создана через настоящий application API, включая продукт и комментарий; изображение получено через HTTP. Его SHA-256 до и после обоих переключений: `c232048b9fae8a8bc97d0ea03319ff85a9347d39a304ef20a9e54f14e5327d76`. Приватные пароли и raw env не входят в публичные отчёты. Все пять durable operations завершились `succeeded`; финальный сервис работает после Rollback, Docker health всех трёх компонентов — `healthy`. Зафиксированный финальный адрес — `http://127.0.0.1:32854`; при следующем пересоздании случайный порт изменится.

Схема БД в этом сценарии не менялась: оригинальный `run.sh` компилирует TypeScript и выполняет неизменённые миграции при старте API. Данные при Rollback не откатывались. Проверки — Docker healthchecks и отдельные легитимные HTTP probes, а не подключённый panel functional checker; organizer checker, exploits, private GitLab, moving branch, offline registry и native Linux/amd64 в этом прогоне не проверялись. Принятие исходного upstream Compose и совместимость произвольных изменений схемы из этого результата не следуют.
