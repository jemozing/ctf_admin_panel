# CTF Service Manager

[MIT](LICENSE) · [Разработка и проверки](CONTRIBUTING.md) · [Сообщения об уязвимостях](SECURITY.md)

Панель управления сервисами одной команды на Attack/Defense CTF. Проект разрабатывается по [техническому заданию](docs/technical-specification.md), начиная с контрактов, тестового стенда и локального executor.

**Текущий статус:** реализована рабочая вертикаль MVP: Compose `dashboard + executor`, авторизация/RBAC, регистрация, baseline, Prepare/Build, Deploy/Rollback, восстановление прерванной операции, журнал, метрики хоста и контейнеров с часовой историей. Сквозные проверки выполняются на синтетическом стенде. Полная приёмка MVP на боевом Linux-хосте ещё не завершена; подтверждения и оставшиеся пункты перечислены в [состоянии разработки](docs/progress.md).

Реализован отдельный opt-in HTTP Proxy с журналом трафика и базовым WAF: страницы «Трафик» / «Proxy / WAF», маршруты на свободных портах, фильтры сервисов, rate/burst по IP и временные баны. Есть HTTP/1.1, отдельный HTTPS/2→h2c/gRPC профиль, TLS termination и подтверждённый групповой перенос/возврат занятых портов нескольких application-компонентов и TCP-портов одного сервиса. Соревновательная приёмка на VM остаётся открытой. [Установка](docs/http-proxy-install.md), [план и матрица P01–P16](docs/http-proxy-waf-plan.md). По решению пользователя повторные проверки нестабильной VM отложены; это не закрывает приёмку MVP.

Добавлено независимое пассивное наблюдение TCP/UDP: «Трафик → Пакеты», фильтры, hex/ASCII и экспорт PCAP. Подключение — opt-in Linux capture, по умолчанию только метаданные. Реализованы TCP-потоки/UDP-датаграммы, HTTP2/gRPC и protobuf descriptors с привязкой к версии; [использование](docs/traffic-analysis.md). [Установка](docs/packet-capture-deployment.md), [контракт и матрица C01–C10](docs/packet-capture-plan.md). Локальные fixtures проверены; живой Linux capture и нагрузка ещё не приняты.

## Основной запуск: Docker Compose

На Linux Docker-хосте подготовьте отдельные каталоги и список разрешённых игровых проектов. Bootstrap не меняет существующие сервисы:

```sh
sudo python3 scripts/compose-bootstrap.py \
  --host-metrics \
  --discovery-root /srv/game-services \
  --workspace-root /srv/ctf-workspaces
sudo docker compose --env-file /srv/ctf-manager/config/compose.env config --quiet
sudo docker compose --env-file /srv/ctf-manager/config/compose.env build
```

Создайте первого администратора локальным `init-admin` в контейнере dashboard по [инструкции](docs/container-deployment.md), затем:

```sh
sudo docker compose --env-file /srv/ctf-manager/config/compose.env up -d --build
```

`dashboard` работает с UID 10001 и публикуется только на `127.0.0.1:8765`. `executor` получает Docker socket и явно разрешённые host-каталоги. Игровые проекты остаются независимыми от Compose панели. Подробные шаги создания администратора, права каталогов, SSH-доступ и ограничения — в [инструкции контейнерного развёртывания](docs/container-deployment.md).

## Сборка и проверки

Требуются Go 1.26+, Node.js 22.12+ и npm. `make build` собирает React/TypeScript frontend и встраивает его в Go-бинарник. Первичная загрузка зависимостей требует сети; версии закреплены в Go и npm lock-файлах. Dockerfile выполняет эти шаги самостоятельно.

```sh
make build
make proxy-build capture-build
make test
make test-race
make vet
bin/ctf-manager version
```

Кеш Go размещается в `.cache/` проекта. Бинарники находятся в `bin/`, локальное состояние — в игнорируемом `var/`. Исходники сторонних сервисов загружаются в игнорируемый vendor-каталог; приложение не запускает их exploit/checker-скрипты.

GitHub Actions выполняет сборку frontend, Go race/vet, helper-тесты, проверки упаковки/fixtures и сборку пяти бинарников на Linux. Нагрузочные и аварийные сценарии требуют отдельного стенда.

В репозиторий входят исходники, lock-файлы, примеры конфигурации и документация. Секреты, рабочее состояние, сборки, загруженные игровые проекты и сырые отчёты исключены; [публичная сводка проверок](tests/integration/reports/README.md) сохраняет статусы и ограничения. Перед публикацией выполните `make publication-check` после `git add .`: проверяются файлы из Git index.

Восстанавливаемые каталоги `.cache/`, `web/node_modules/`, `var/preview/minio-gocache/` и `var/preview/minio-modcache/` можно удалять при остановленных сборках. Следующий `make build` загрузит зависимости заново. Сохраняйте остальные файлы `var/`: там находятся настройки, состояние, секреты и данные стендов.

## Локальная разработка

Требуются Docker Engine и Compose plugin. На macOS используется явный development-профиль; он не подтверждает разделение UID и эксплуатационные гарантии Linux.

```sh
python3 scripts/dev-bootstrap.py
bin/ctf-manager --config var/executor.dev.json doctor
bin/ctf-manager --config var/executor.dev.json inventory --project ctfm-example
```

Для проверки Compose без изменения контейнеров:

```sh
bin/ctf-manager --config var/executor.dev.json inspect-project \
  --directory /absolute/path/inside/approved/root \
  --project existing-compose-project \
  --files compose.yaml
```

`inspect-project` читает только проект внутри заранее разрешённого корня. Compose получает защищённые копии YAML/env-входов; вывод скрывает значения environment. Возможные проблемы профиля возвращаются отдельными diagnostics и блокируют регистрацию.

Локальный executor и отдельный клиент состояния:

```sh
bin/ctf-manager --config var/executor.dev.json executor
# В другом терминале:
bin/ctf-manager --config var/executor.dev.json status
```

Executor использует Unix socket с проверкой UID клиента. Фиксированные API предоставляют реестр, состояние, предпросмотр и долговечные операции. Любая операция требует свежего `plan_digest`; после аварии шаги не повторяются автоматически. Собственный stale socket восстанавливается под эксклюзивной блокировкой; живой или чужой socket не удаляется.

## Регистрация

Политика сервиса включает подтверждённые container/image IDs, project name, управляемые пути, отдельный source workspace и классификацию всех хранилищ. Подробности — в [инструкции регистрации](docs/registration.md).

Основной сценарий MVP — через панель: войдите как Admin → «Добавить сервис» → укажите host-путь существующего Compose-проекта внутри разрешённого корня → проверьте компоненты, пути кода и хранилища → просмотрите и подтвердите заявку. CLI не требуется. Панель автоматически ставит создание baseline и source workspace в очередь; до завершения инициализации обновление недоступно. Повтор подтверждения не создаёт второй сервис.

Путь можно выбрать кнопкой «Выбрать папку»: откройте разрешённый каталог Docker-хоста, перейдите к сервису и нажмите «Выбрать эту папку». Ручной ввод сохранён. Выбор папки не запускает сервис: его Compose-контейнеры должны уже существовать.

GitHub/GitLab подключаются необязательным HTTPS Git URL при добавлении или на вкладке «Git-источник». Укажите ref и при необходимости подкаталог и read-only токен. «Получить из Git» создаёт отдельный кандидат с точным SHA; далее Build → Deploy. Для локальных правок workspace сохраняется Prepare → Build → Deploy. В MVP Git-сервер должен иметь публично маршрутизируемый адрес и доверенный TLS; SSH, private-network GitLab и API провайдеров остаются расширениями.

Дополнительный локальный административный способ:

```sh
bin/ctf-manager --config var/executor.dev.json propose --service service.json
bin/ctf-manager --config var/executor.dev.json approve \
  --proposal proposal-REVIEWED_ID --digest sha256:REVIEWED_DIGEST
bin/ctf-manager --config var/executor.dev.json services
```

Подтверждение относится к неизменяемой заявке и её digest. Оно не запускает и не пересоздаёт контейнеры. В локальном CLI-сценарии после регистрации создайте baseline через Snapshot; веб-сценарий делает это автоматически. Прежде чем применять изменения, изучите [pipeline релизов и восстановления](docs/release-pipeline.md).

## Документация

- [ТЗ, границы MVP и этапы](docs/technical-specification.md).
- [Обязательный функционал MVP и границы приёмки](docs/mvp-functionality.md).
- [План HTTP Proxy, страницы трафика и WAF после MVP](docs/http-proxy-waf-plan.md).
- [Пассивные TCP/UDP пакеты, PCAP и матрица C01–C10](docs/packet-capture-plan.md).
- [TCP-потоки, gRPC/descriptors и HTTPS/2 termination](docs/traffic-analysis.md).
- [Установка отдельного capture-профиля](docs/packet-capture-deployment.md).
- [Установка dashboard + executor через Docker Compose](docs/container-deployment.md).
- [Dashboard, роли и API](docs/dashboard.md).
- [Релизы, локальные проверки и восстановление](docs/release-pipeline.md).
- [Git URL, credentials и ограничения источников](docs/git-sources.md).
- [Контракты данных](docs/contracts.md).
- [Модель угроз и границы доверия](docs/threat-model.md).
- [Профиль Compose](docs/compose-profile.md).
- [Ротация и квоты](docs/storage.md).
- [Метрики хоста и история за 60 минут](docs/metrics.md).
- [TCP/HTTP-проверки и ручные подтверждения](docs/health-checks.md).
- [Очередь, лимиты параллельности и приоритет Rollback](docs/scheduler.md).
- [Логи и долговечная диагностика операций](docs/logging.md).
- [Версии секретов и локальное обслуживание](docs/secrets.md).
- [Обычный экспорт и зашифрованный backup/restore](docs/backup.md).
- [Хранение и восстановление операций](docs/persistence.md).
- [Локальный протокол executor и проверка UID](docs/executor-protocol.md).
- [Тестовый стенд и HTTP-контракт](docs/testing.md).
- [Пять реальных сервисов SibirCTF](docs/real-services.md).
- [Состояние этапов и подтверждённые проверки](docs/progress.md).
