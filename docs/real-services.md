# Реальные сервисы SibirCTF

На 19 октября 2026 года выбраны ровно пять сервисных репозиториев [SibirCTF](https://github.com/SibirCTF). Все содержат LICENSE MIT. Ревизии закреплены в `tests/real-services/services.lock.json`, исходники загружаются только в игнорируемый каталог `tests/fixtures/vendor/`. Проверка ревизии, чистоты checkout и SHA-256 просмотренных файлов обязательна перед использованием.

| Сервис | Ревизия | Контейнеры | Локальный вход этапа 0 | Итог статического ревью |
|---|---|---|---|---|
| [EyeSee](https://github.com/SibirCTF/2025-cybersibir-service-eyesee/tree/2eda1b05fe6e025c3f1bec25f762f3ad01d6a74c) | `2eda1b05fe6e025c3f1bec25f762f3ad01d6a74c` | Go gRPC + MinIO | `127.0.0.1:27910` | Config OK; данные MinIO требуют inspect |
| [CyberBank](https://github.com/SibirCTF/2025-cybersibir-service-bank/tree/4a7d4eafb2e8030aa230316e3f191908a2b0437a) | `4a7d4eafb2e8030aa230316e3f191908a2b0437a` | Node API + nginx/React + PostgreSQL | `http://127.0.0.1:27337` | Config OK; смешанные code/data mounts |
| [NightCity Data Exchange](https://github.com/SibirCTF/2025-cybersibir-service-ncdex/tree/435b7108d3b8c2693467a9e4be8a5c71b0936d64) | `435b7108d3b8c2693467a9e4be8a5c71b0936d64` | Crystal + PostgreSQL | `http://127.0.0.1:27331` | Config OK; ошибочный upstream DSN |
| [BioGuard](https://github.com/SibirCTF/2025-cybersibir-service-BioGuard/tree/0d5dffae3460823715a266d5674d2110837c4bea) | `0d5dffae3460823715a266d5674d2110837c4bea` | Django + SQLite | `http://127.0.0.1:27444` | Config OK; SQLite в writable layer блокирует recreation |
| [neuroLinks 2-3-4](https://github.com/SibirCTF/2025-cybersibir-service-neLi234/tree/28d8a11498675233e87394e4d89956ad0938abfd) | `28d8a11498675233e87394e4d89956ad0938abfd` | C++ controller + Go binary | TCP `127.0.0.1:27340` | Config OK; SQLite в layer, непрозрачный бинарник |

Таблица описывает исходную статическую проверку этапа 0 и её фиксированные тестовые порты. `Config OK` означает успешный `docker compose config --format json` и проверку портов, mounts и привилегий; на этом этапе контейнеры не запускались. Последующие реальные браузерные прогоны используют отдельные адаптированные профили с динамическими loopback-портами и описаны ниже. Они не подтверждают безопасное пересоздание исходного upstream Compose без подготовки данных.

## Подготовка

Требуются Python 3.9+, Git и Docker Compose >= 2.24.4 (`!override` полностью заменяет исходные ports; обычное объединение списков сохранило бы wildcard-публикации).

```sh
python3 scripts/fetch-real-services.py fetch
python3 scripts/fetch-real-services.py verify
python3 scripts/fetch-real-services.py config
python3 scripts/fetch-real-services.py config --id bioguard
python3 -m unittest discover -s tests/real-services -p 'test_*.py' -v
```

`fetch` получает конкретный commit через HTTPS и detached checkout. Существующий каталог принимается только при совпадении origin и SHA, без изменённых или неотслеживаемых файлов. Автоматический reset локальных изменений не выполняется. Git hooks отключены, submodules и скрипты репозиториев не запускаются. Скрипт не предоставляет build/up/down: он ограничен загрузкой, проверкой и разбором конфигурации.

Пути относительно корня проекта. Машинные карты для будущей регистрации находятся в `tests/real-services/service-maps.json`; это результаты ревью, ещё не разрешения на deploy. Подробные отчёты — `tests/real-services/reports/*.md`.

## Развёртывание на тестовом Linux

Пример корня checkout панели на Linux: `/srv/ctfm/real-services`. Тогда vendor — `/srv/ctfm/real-services/tests/fixtures/vendor`; точные шаблоны путей каждого сервиса записаны в `linux_source_template` lock-файла. При другом размещении необходимо подставить фактический абсолютный путь. Compose-файл находится внутри `<vendor>/<repository>/vuln-service/`, а override остаётся вне upstream-каталога. Игровые volumes не входят в snapshot или release.

Перед любым запуском нужны `image inspect` и `container inspect`: образ может объявлять VOLUME, отсутствующий в Compose. Поэтому отчёт не подменяет mount-инвентаризацию работающего Docker. Для обновлений сначала подтверждаются все data mounts и их ID, согласуется миграционная политика и сохраняются точные image ID. У каждого проекта отдельное имя `ctfm-real-*`, все опубликованные TCP-порты привязаны к `127.0.0.1`, фиксированный `container_name: bioguard` сброшен. Оригинальные mount и data-настройки не исправлены скрыто.

Override выключает автоматический restart тестовых контейнеров и ограничивает публикацию портов. Он не является песочницей для запуска потенциально уязвимого кода. Внешние jury, exploit и checker Compose-файлы не используются. Проверки направляются только на локальные тестовые endpoints. Для EyeSee и neurolink требуется Linux amd64 или явно доступная эмуляция; это отражено в override.

## Сценарии использования

1. Сверить Compose-инвентаризацию панели с `service-maps.json`: компоненты, mounts, роли, секреты и управляемые файлы.
2. Проверить, что registration не разрешает recreation при SQLite в layer или неразобранных mounts.
3. На CyberBank проверить обнаружение игровых картинок внутри anonymous `/app/build` и отделение их от артефактов сборки.
4. На ncdex убедиться, что `depends_on` и открытый порт не засчитываются как функциональная исправность при неверном DSN.
5. На EyeSee проверить отсутствие неявного пересоздания MinIO при выборе только `eyesee-service`.
6. После отдельной подготовки data layout использовать локальные put/get-пробы синтетических данных; организаторский checker остаётся отдельным сигналом.

Не применять `down -v`, prune с удалением volumes или очистку vendor с игровыми данными. Исходники остаются gitignored. Статические карты исходного Compose и фактически проверенные адаптированные runtime-профили имеют разный объём доказательств.

## Адаптированные профили: браузерная регистрация и релизный цикл

В постоянном preview каждый сервис добавляется через мастер по native Linux пути `/srv/ctf-manager-preview/services/sibir-<id>`. В панели подтверждаются классификация хранилищ, immutable proposal, публичный Git URL и точный commit из таблицы. Helpers подготавливают отдельные исходные Compose-проекты до регистрации, создают синтетические игровые записи и читают результаты; они не регистрируют сервисы и не отправляют Fetch/Build/Deploy/Rollback. Порты опубликованы только на `127.0.0.1`, их текущие значения записаны в отчётах.

Все пять адаптированных сервисов прошли браузерную регистрацию и полный Git Fetch → Build → Deploy → Rollback с сохранением игровых данных. [Сводный отчёт последних четырёх циклов](../tests/integration/reports/README.md#report-sibir-four-web-cycles-2026-10-19-json) дополняет ранее проверенный BioGuard. Четыре новых сервиса оставлены работающими на импортированных baseline, собранные Git-релизы сохранены. У BioGuard в этом интервале отдельно наблюдались Build и Rollback на ранее собранный Git-релиз; текущее состояние оставлено без вмешательства, сохранность пациента повторно подтверждена. Эти операции отделены в сводном отчёте от четырёх новых циклов.

| Профиль | Что собирается и переключается | Сохраняемые данные и проверка |
|---|---|---|
| [BioGuard — passed](../tests/integration/reports/README.md#report-sibir-bioguard-web-cycle-2026-10-19-json) | Настоящий Django из неизменённого upstream Dockerfile; `migrate` и `runserver --noreload` | SQLite named volume `/data`, frozen readonly settings вне Git-кода; свежий HTTP login читает прежний diagnosis |
| [ncdex — passed](../tests/integration/reports/README.md#report-sibir-ncdex-web-cycle-2026-10-19-json) | Настоящий Crystal из upstream Dockerfile; цель только `app` | PostgreSQL named volume; исправленный DSN на внутренний `db:5432`, отдельная frozen init/config; свежий login читает ту же игровую запись |
| [CyberBank — passed](../tests/integration/reports/README.md#report-sibir-bank-web-cycle-2026-10-19-json) | Оба upstream Dockerfile: Node API и React/nginx; PostgreSQL исключён из targets | Отдельные named volumes PostgreSQL и `/app/build/static/images`; свежий login, тот же продукт/content/комментарий и точный SHA-256 PNG |
| [neLi234 — passed](../tests/integration/reports/README.md#report-sibir-neli234-web-cycle-2026-10-19-json) | Пересобираемый C++ `controller` на arm64 — единственная цель; opaque amd64 `neurolink` работает через эмуляцию | `working_dir=/data` выносит относительный `messages.db` в named volume; TCP login после Rollback читает исходные и созданные под Git-релизом SQLite thoughts и RAM concepts; aux container не менялся |
| [EyeSee — passed](../tests/integration/reports/README.md#report-sibir-eyesee-web-cycle-2026-10-19-json) | Upstream production Dockerfile упаковывает поставляемый amd64 executable; app исполняется через эмуляцию, MinIO исключён из targets | MinIO named volume; gRPC `AddPrescription`, `CheckPrescription`, `GetPrescriptionIDs` подтвердили prescription и связь с пациентом после Deploy/Rollback |

До регистрации профили приведены к поддерживаемому Compose: явно задан `shm_size: 64m`, приватные CyberBank env inputs перенесены внутрь исключённого `secrets/` проекта, у neLi234 убраны неподдерживаемые `platform`/`tmpfs` из runtime-модели. Архитектуры его образов выбираются при начальной сборке, controller остаётся read-only; frozen конфигурация во время этих циклов не меняется после регистрации. У ncdex исходные настройки PostgreSQL под 16 GiB заменены явными ограниченными параметрами, схема и seed сохранены. У CyberBank управляется `vuln-service` с единственным исключением `.env`; восемь TypeScript-файлов `src/db` и необходимый `front/.nginx/nginx.conf` включены в Git candidate.

Исторические образы MinIO оказались недоступны в registry, архив бинарника вернул HTTP 410. Для EyeSee отдельно собран Linux/arm64 MinIO из официального `RELEASE.2025-02-28T09-55-16Z`, commit `8c2c92f7afdc8386b000c0cb57ecec2ee1f5bcb0`, затем упакован в локальный storage image. Это не сборка Go-исходников приложения EyeSee. У neLi234 RAM сохраняется благодаря отсутствию restart/recreation `neurolink`; долговечность этой памяти после перезапуска не заявляется.

Все прогоны используют импортированный локальный baseline с явно документированной меткой и один точный upstream commit: HTML для BioGuard/ncdex/CyberBank, TCP-меню для neLi234 и Docker LABEL для EyeSee. Это не сравнение двух upstream revisions. Проверяются immutable manifests, точные image IDs, неизменность frozen configuration, data volume identity и записей после переключения. Неизменившийся API CyberBank законно использует тот же cached image; frontend получает другой образ. Приватные env inputs, пароли и cookie jar не включаются в публичные отчёты.

Результаты ограничены OrbStack Linux/arm64 с отмеченной amd64-эмуляцией, Docker healthchecks и отдельными легитимными application probes. Организаторские checkers/exploits, native Linux/amd64, moving refs, private GitLab, offline registry и совместимость миграций схемы остаются отдельными испытаниями. Подробности каждого профиля находятся в `tests/real-services/reports/*.md`; общая матрица — [progress.md](progress.md).

В истории neLi234 сохранён один корректный отказ первого Fetch: upstream `sqlite3.c` размером 9 235 994 байта превышал прежний лимит файла 8 MiB; активный baseline и игровые данные сохранились. После изменения только файлового лимита до 16 MiB повторный Fetch и Build прошли. Этот исправленный отказ не удаляется из журнала операций и не подменяется утверждением, что все исторические попытки были успешными.
