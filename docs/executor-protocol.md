# Локальный протокол executor v1

`internal/transport` предоставляет HTTP/1.1 поверх одного Unix stream socket. TCP listener и сетевой fallback отсутствуют. `NewClient` всегда соединяется с заранее настроенным socket и не следует redirects; proxy environment не изменяет маршрут. Публичный web API к этому протоколу напрямую не выставляется.

Production transport требует Linux. На macOS запуск разрешается только с явным `Development: true` и предназначен для разработки. Linux использует `SO_PEERCRED`, macOS — `LOCAL_PEERCRED`. HTTP identity и заголовки не заменяют peer UID.

Для выбора папок регистрации предусмотрен `POST /v1/registration/directories` с JSON `{"directory":""}` для списка discovery roots либо с точным каноническим host-путём. Ответ содержит `directory`, необязательный `parent`, `directories: [{name,path}]`, `compose_files` и `truncated`. Возвращаются только имена каталогов и четырёх стандартных Compose-файлов; содержимое не читается. Обход, ссылки и подмена identity при открытии отклоняются. Лимиты: 4096 просмотренных записей, 256 каталогов, 64 КиБ имён/путей; запрос ограничен общими правилами регистрации (строгий JSON, без query parameters). Web-прокси дополнительно требует Admin и CSRF. Этот read-only маршрут не обращается к Docker и не меняет конфигурацию корней.

## Socket и доступ

Socket создаётся с mode `0660` в отдельном каталоге, который не является symlink и не доступен на запись группе/остальным. Установщик задаёт владельца/группу, необходимые для web UID и executor UID, и защищает всю иерархию служебных каталогов. `AllowedUIDs` указывается явно, скрытого исключения для UID 0 нет.

Текущий `Options` не меняет GID socket через chown: socket наследует эффективную группу executor. Для установки нужна общая IPC-группа, например `ctf-manager-ipc`: в Compose executor запускается как `0:10001`, dashboard — как `10001:10001`. Каталог `/run/ctf-manager` и все его закрытые предки должны разрешать группе traverse (`0750`, владелец executor, группа IPC). Сам web UID остаётся отдельным, без членства в Docker group. При socket `0660` и недоступном предке соединение не дойдёт до проверки peer credentials.

Доступ к runtime socket не означает доступ к состоянию. Private state, БД и secrets executor имеют отдельный root с mode `0700`, файлы — `0600`; общая IPC-группа не должна получать к ним доступ. Каталог runtime остаётся без группового write, чтобы web UID не мог заменить socket path. Production unit и установщик должны проверять эти разрешения вместе с UID allowlist.

Daemon включает `RecoverStaleSocket`: перед восстановлением своего stale socket он захватывает приватный flock и подтверждает ECONNREFUSED. Живой, чужой или подменённый socket не удаляется. В режиме transport без этого явного option существующий socket отклоняется. После штатного закрытия удаляется только socket с тем же inode, которым владеет экземпляр server.

Любой endpoint сначала проверяет полученный от ОС peer UID. Допускаются Host `executor`/`localhost`, Origin должен отсутствовать. Query parameters разрешены только для фиксированного log endpoint и выбора зарегистрированного компонента истории метрик; encoded path variants отклоняются. HTTP parser ограничивает заголовки и время чтения; POST body ограничен 1 MiB. Shutdown по context имеет ограниченное время завершения запросов и затем закрывает соединения.

## Endpoints

| Метод и путь | Ответ |
|---|---|
| `GET /v1/health` | `{ "status": "ok", "schema_version": 1 }` |
| `GET /v1/services` | JSON array текущих утверждённых Service без раскрытых секретов |
| `GET /v1/registration/options` | Разрешённые discovery/workspace roots для мастера Admin |
| `POST /v1/registration/inspect` | Черновик регистрации существующего проекта по разрешённому пути |
| `POST /v1/registration/proposals` | Неизменяемая заявка после проверки конфигурации/runtime |
| `POST /v1/registration/approve` | Подтверждение по proposal ID/digest и инициализация workspace/baseline |
| `GET/POST /v1/services/<service_id>/source` | Безопасные метаданные / настройка HTTPS Git URL/ref и write-only credential |
| `GET /v1/operations` | JSON array долговечных Operation |
| `GET /v1/operations/<operation_id>` | Одна операция либо 404 |
| `POST /v1/operations` | 202 с сохранённой Operation |
| `POST /v1/preview` | План и digest до изменения |
| `GET /v1/services/<service_id>` | Фактическое состояние, релизы, снимки и разрешённые действия |
| `GET /v1/services/<service_id>/logs?component=app&tail=200` | Ограниченные логи зарегистрированного компонента |
| `GET /v1/services/<service_id>/metrics?component=app` | Последний срез компонентов и до 60 минут истории одного зарегистрированного компонента; selector необязателен |
| `GET /v1/metrics/host` | Кеш host-метрик и до 60 минут RAM-истории с nullable/source/scope evidence |
| `GET /v1/operations/<operation_id>/events` | Журнал операции |

Пример минимального Submit после просмотра плана:

```json
{
  "service_id": "flags",
  "action": "deploy",
  "release_id": "release-1",
  "idempotency_key": "811fd64e3da94ea18fdc327e",
  "plan_digest": "sha256:REVIEWED_PREVIEW_DIGEST",
  "confirm_data_compatibility": true
}
```

`service_id` и необязательный `release_id` проходят ID validation. `release_id` обязателен для Deploy/Rollback. Действия принадлежат закрытому набору `start`, `stop`, `restart`, `prepare`, `build`, `deploy`, `snapshot`, `rollback`, `recover`, `fetch_source`; daemon подключает runner для этих действий. Ключ идемпотентности — 1–128 printable ASCII bytes без whitespace.

Операционный Submit не принимает пути, shell-команды, Compose arguments, environment, пользовательские UID или изменения политики. Отдельные методы регистрации принимают только типизированный путь/проверяемую заявку внутри bootstrap-корней. Неизвестные, дублирующиеся и иначе регистрированные имена полей, значения `null`, неверные типы и дополнительные JSON-документы отклоняются (`confirm_data_compatibility` — boolean, остальные поля — строки) до вызова backend. Даже при отключённом submission сначала выполняется проверка тела.

Backend получает `Principal` с подтверждённым peer UID/GID и типизированный `SubmitRequest`. Он обязан повторно проверить текущую доверенную политику, вычислить semantic input hash, resource locks и доступность артефактов. Transport не разрешает выполнить действие только потому, что его имя прошло syntactic validation. Долговечная идемпотентность и очередь находятся в executor/store, а не в HTTP handler.

Подтверждение новой регистрации по proposal ID/digest доступно через отдельный типизированный endpoint. Dashboard допускает к нему только Admin после проверки сессии/CSRF и устанавливает инициатора сам; peer UID не заменяет пользовательскую роль. Executor повторно проверяет неизменяемую заявку по bootstrap-корням, профилю, runtime и конфликтам. Регистрация не разрешает произвольное изменение корней или Compose-привилегий. CLI остаётся дополнительным административным инструментом, но не обязательным этапом веб-регистрации.

## Ошибки

Ошибки имеют формат `{ "code": "invalid_request", "message": "..." }`. Основные HTTP codes: 400 некорректная схема/ID, 403 peer/Host/Origin, 404 неизвестный объект, 405 метод, 409 конфликт состояния/идемпотентности, 413 body limit, 415 content type, 501 отсутствующая операция backend. Внутренние ошибки не раскрывают SQL, secrets, пути и вывод Docker; подробности относятся к защищённому журналу executor.

## Проверки

`go test -race ./internal/transport` использует настоящий Unix socket и credentials текущего UID. Проверяются allowlist denial, Host/Origin/path rules, command/path injection, duplicate fields, oversized body, nil submission, удержание active socket, сохранение подменённого inode, mode `0660` и context shutdown. На macOS тестам может требоваться разрешение sandbox на локальный bind.

Успешный cross-build `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./internal/transport` проверяет Linux API на уровне компиляции. Тест текущего UID на macOS не заменяет проверку разных Linux UID.

### Проверенное разделение UID на Linux

19 октября 2026 года `TestLinuxUIDIsolation` выполнен в изолированном Docker-контейнере `linux/arm64`. [Отчёт](../tests/integration/reports/README.md#report-executor-peer-linux-2026-10-19-json) содержит точный image ID, effective capabilities, UID/GID/PID helpers, modes и результаты доступа.

| Проверка | Результат |
|---|---|
| Executor `UID 0:GID 10001`, runtime `0750`, socket `0660` | Проверены фактические ownership/modes |
| Helper `UID 10001:GID 10001`, allowlist содержит только 10001 | Успешные health/services; callback получает его реальный UID/GID/PID через Linux `SO_PEERCRED` |
| Helper `UID 10002:GID 10001`, та же IPC-группа | Unix dial успешен, health/services возвращают 403 по peer UID |
| Оба helpers против private directory `0700`, actual SQLite/secret files `0600` | List/read/write запрещены ОС |
| Capabilities helpers | Пустые после смены UID |
| Capabilities test executor | Только SETUID/SETGID (`CapEff=00000000000000c0`) для запуска helpers |
| Контейнер | Root filesystem read-only, только loopback, Docker socket отсутствует |

UID 0 нужен только тестовому родителю, чтобы создать subprocesses с разными credentials. В выбранном Compose-профиле production executor работает как UID 0:GID 10001; dashboard остаётся UID 10001. Доказаны kernel peer credentials и файловая изоляция; доступ production executor к Docker и изоляция двух Compose-контейнеров проверяются отдельно в compose-smoke.

Тест opt-in и без `CTFM_LINUX_UID_PROOF=1` пропускается, поэтому обычный `go test` не требует root или смены пользователей на хосте. Для повторения сначала соберите test binary (выберите архитектуру Docker-хоста):

```sh
mkdir -p /tmp/ctfm-peer-proof/output
chmod 0777 /tmp/ctfm-peer-proof/output
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c \
  -o /tmp/ctfm-peer-proof/transport.test ./internal/transport
```

В изолированный уже загруженный fixture image передаются только этот binary read-only и временный output directory. Команда запуска должна включать:

```sh
docker run --rm --pull never --network none --read-only \
  --user 0:10001 --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges --pids-limit 96 --memory 256m --cpus 1 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 \
  --mount type=bind,source=/tmp/ctfm-peer-proof/transport.test,target=/proof/transport.test,readonly \
  --mount type=bind,source=/tmp/ctfm-peer-proof/output,target=/out \
  --env CTFM_LINUX_UID_PROOF=1 \
  --env CTFM_UID_REPORT=/out/executor-peer-linux.json \
  --env CTFM_UID_IMAGE_ID=<exact-local-image-id> \
  --entrypoint /proof/transport.test <exact-local-image-id> \
  -test.run '^TestLinuxUIDIsolation$' -test.v -test.count=1
```

Output directory предварительно создаётся с правом записи для container root; он содержит только несекретный тестовый отчёт. Docker socket, исходники панели и игровые каталоги в контейнер не монтируются. Контейнер не скачивает зависимости и не обращается к сети. Для обязательного linux/amd64 target test binary также успешно cross-built; runtime-проверка данного отчёта выполнена на linux/arm64.


## Реализованная вертикаль dashboard/executor

Текущий daemon подключает долговечный runner: фиксированные actions Snapshot/Prepare/Build/Deploy/Rollback/Start/Stop/Restart и явный Recover. Детали, preview, events, bounded logs и cached metrics доступны через типизированные методы `internal/transport`. Submit не принимает пути, команды, flags или Compose-объекты. `plan_digest` обязателен для любого изменяющего запроса. `initiator` dashboard устанавливает по серверной сессии. Recover принимает `recovery_operation_id`, сохраняет отдельное намерение и работает под исходными блокировками. Источником точной схемы JSON служат `SubmitRequest`, `PreviewResult`, `ServiceDetails` и `MetricsResponse`.

Daemon включает безопасное восстановление своего stale socket: соседний приватный lock-файл, flock, проверка владельца/типа, отказ для живого endpoint и удаление только неизменившегося socket с подтверждённым ECONNREFUSED. Завершение процесса снимает flock; lock-файл не удаляется для предотвращения гонки inode.

Публичные значения environment отсутствуют в DTO. Полный build stdout не выдаётся в Web, поскольку Dockerfile может вывести секрет; журнал хранит ограниченные digest/size evidence. Доступ к прикладным логам отдельно контролируется dashboard.
