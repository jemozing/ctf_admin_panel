# EyeSee — реальный цикл через панель

Источник: [SibirCTF/2025-cybersibir-service-eyesee](https://github.com/SibirCTF/2025-cybersibir-service-eyesee/tree/2eda1b05fe6e025c3f1bec25f762f3ad01d6a74c), commit `2eda1b05fe6e025c3f1bec25f762f3ad01d6a74c`, LICENSE MIT.

19.10.2026 сервис зарегистрирован через браузер по пути, Git URL подключён и подтверждён в мастере. Fetch → Build → Deploy → Rollback прошли через панель, пять durable operations вместе с автоматическим baseline snapshot завершились `succeeded`. Существующий рецепт и связь с patient_id сохранились. Полный публичный [отчёт с phase evidence и 15 проверенными assertions](../../integration/reports/sibir-eyesee-web-cycle-2026-10-19.json) содержит точные operation/release/image ID, хэши, архитектуры и provenance MinIO.

Профиль явно адаптирован: supplied amd64 ELF выполняется через эмуляцию на Linux/arm64, а недоступный исторический MinIO image заменён локальной сборкой его закреплённых официальных исходников. Docker Build EyeSee упаковывает готовый upstream бинарник; компиляция Go-приложения из `dev/service` в этом прогоне не заявляется.

## Профиль и сохранение данных

Проект `ctfm-preview-sibir-eyesee`, каталог `/srv/ctf-manager-preview/services/sibir-eyesee`, frozen runtime Compose `ctfm.runtime.yaml`. Managed code — весь `vuln-service`, без исключений: ровно три Git blob (`Dockerfile`, `docker-compose.yaml`, `eyesee`). Git subdirectory пустой. Upstream Compose сохраняется как исходный файл, но фактический запуск использует отдельный подтверждённый локальный профиль.

| Компонент | Роль и вход | Данные и политика |
|---|---|---|
| `eyesee-service` | Application, единственный update target; gRPC 25910 опубликован на случайном loopback host port; rootfs read-only | Рецепты передаются в MinIO; writable layer временный |
| `eyesee-storage` | Data component с ролью database, исключён из update targets; S3 9000 и console 9001 наружу не опубликованы | Named volume `ctfm-preview-sibir-eyesee_minio-data` → `/data`, significant preserve |

App ограничен 256 MiB и 0.5 CPU, storage — 512 MiB и 0.5 CPU; обоим заданы `shm_size:64m`, 128 PID и ротация логов. Поле `platform` исключено из локального frozen Compose как неподдерживаемое нормализатором; фактические архитектуры проверены image inspect и описаны ниже. Hash runtime Compose не менялся в принятом цикле.

Официальные исторические MinIO images вернули registry denied/unauthorized, архив готового бинарника — HTTP410. Для storage использован официальный tag `RELEASE.2025-02-28T09-55-16Z`, commit `8c2c92f7afdc8386b000c0cb57ecec2ee1f5bcb0`, чистый checkout. Сборка выполнена с `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=arm64`, параллелизмом 2, Go1.26.5. Полученный бинарник упакован на `python:3.11-slim`. SHA256 фактического `/usr/local/bin/minio` в работающем контейнере совпал с build provenance: `366ef54345ada2ac012924580ba6a37f5d46336b26de242e38fe5214c6545b71`, 148421234 байт. Version string `DEVELOPMENT.GOGET` относится к обычной локальной Go-сборке и не выдаётся за vendor-built release artifact.

## Результаты цикла

| Действие через панель | Результат | Время |
|---|---|---|
| Автоматический baseline snapshot | `succeeded`, импорт текущего кода и образов | 0.380 с |
| Fetch exact Git commit | `succeeded`, candidate `snap-071f3aaea56aae0d7911efbe8623eb7e` | 2.729 с |
| Build | `succeeded`, реальная upstream Docker packaging build | 4.947 с |
| Deploy | `succeeded`, Git release `rel-367469aa4ecf337c5ef1fbedc65e5d40` | 1.210 с |
| Rollback | `succeeded`, baseline `rel-347a78a475904846424c456f5c5e9b4a` | 1.063 с |

Baseline отличается от точного Git commit только безвредным Dockerfile LABEL `org.ctfm.imported-baseline`. Dockerfile уменьшается `197→139` байт после Git Fetch/Deploy. В четырёх manifest entries нет добавлений или удалений: три изменения касаются только GID `0→10001`, ещё одно — GID и содержимого/размера Dockerfile. UID и mode остаются прежними. После Deploy все три blob и все четыре mode/UID/GID/content entries совпали с candidate snapshot; после Rollback — с baseline snapshot.

Provided статический amd64 ELF `eyesee` размером 14008504 байт сохранил SHA256 `833bddb5d5aa0fb4227ca0403f611d57cb109301439ff3190f00063cfe86e378` на всех этапах. Для его получения executor использует ограниченный per-blob лимит 16 MiB, увеличенный с 8 MiB до регистрации EyeSee; первая Fetch этого сервиса прошла успешно. Git tree/repository quotas остаются отдельными ограничениями.

Регистрация, Fetch и Build не меняли активные контейнеры, StartedAt, образы и active code. Baseline/rollback image — `sha256:4b64717f8cd811b7f7906d7a891f8a2ce6bc40bad06f2497a3d391035b240633`, architecture amd64. Git-built image — `sha256:03bbac53d2e2fd5fad42d3fd01a96f47afca8a725f60953dee3a63bbcc9a2cfc`, base architecture arm64, с тем же amd64 ELF, работающим через эмуляцию. LABEL отсутствовал после Deploy и вернулся с точным исходным образом после Rollback. Новых Build/Fetch operations во время Rollback не появилось.

Один синтетический рецепт создан `AddPrescription` до переключений. На baseline, после Build, Deploy и Rollback проверялись `ServiceHealthCheck` (`OK`), `CheckPrescription` и `GetPrescriptionIDs` через новые gRPC channels. Полный deterministic protobuf payload сохранял SHA256 `cdbbffc6a89298b7b3e4bbfe9df4a632e3147c31b58e45598a74da23e8d6f9a7`, ID и patient relation. После исходного seed новые рецепты не добавлялись: upstream deterministic UUID после перезапуска мог бы перезаписать прежний объект. Helper импортирует только protoc-generated message types; код organizer checker не импортируется, `Debugger` и exploit scripts не запускаются.

MinIO container ID `c095e422754633e56be756862036664fa366f646d3f87c818105e9d797794eac`, StartedAt `2026-10-19T15:14:22.740265417Z`, image `sha256:1eddf5f81b06daf7907a2e1e3f8b730710c168b331c6ddd98302633c82986ef2`, mounts и named volume identity/CreatedAt сохранились на всех этапах. Исходные рецепты не откатывались и не заменялись. Payload пациента и raw runtime config не включены в публичный отчёт.

Конечный gRPC endpoint после Rollback: `127.0.0.1:32857`; порт может измениться при будущем пересоздании app. MinIO healthy, app running; реальная gRPC-проба прошла. Helper: `tests/integration/sibir_eyesee_cycle.py`.

## Границы проверки

Проверены импортированный baseline и один точный upstream commit, без изменения схемы/формата данных. Два upstream commit, native Linux/amd64, GitLab/private credentials, перемещённый ref и Rollback при заблокированной сети остаются отдельными проверками. Docker healthcheck у app отсутствует; panel readiness/local_functional checks не настроены, события Deploy/Rollback содержат `checks_not_configured`, external checker остаётся `unknown`. gRPC-пробы не подменяют эти состояния. Исторический статический override `tests/real-services/compose/eyesee.yaml` не заменяется этим адаптированным локальным профилем; прежний статус `not_run` снят только для описанного прогона.
