# Локальные проверки и ручные подтверждения

Проверки настраиваются Admin во вкладке «Проверки» зарегистрированного сервиса. Это отдельные сигналы `readiness` и `local_functional`; Docker healthcheck, состояние контейнеров, ручное подтверждение и неизвестный checker организаторов остаются независимыми.

## Виды проверок

Старый JSON одиночной HTTP GET-проверки совместим с новой схемой: отсутствие `kind` означает `http`.

```json
[
  {"id":"ready","kind":"tcp","source":"readiness","address":"service:8080","timeout_seconds":3},
  {"id":"version","kind":"http","source":"local_functional","url":"http://service:8080/status","expected_status":200,"body_contains":"expected response","timeout_seconds":3}
]
```

TCP connect подтверждает только готовность соединения и не объявляется функциональной проверкой. HTTP сверяет точный status и необязательную подстроку ответа; тело ограничено 64 KiB, заголовки ответа — 16 KiB. Redirect не выполняется, системные proxy не используются.

`http_sequence` содержит 1..8 `steps`, до 4 `cleanup_steps` и одну исходную HTTP origin. Поддержаны GET, HEAD, POST, PUT, PATCH, DELETE, ограниченные headers/body/status/substring. Cookies существуют только в памяти одной попытки. Заголовки Host, proxy/connection/transfer и другие transport overrides запрещены. Каждый request имеет timeout 1..10 секунд; limits проверяются backend, неизвестные JSON-поля отклоняются.

```json
[
  {
    "id":"synthetic-patient",
    "kind":"http_sequence",
    "source":"local_functional",
    "timeout_seconds":3,
    "side_effects_reviewed":true,
    "cleanup_description":"Delete only the dedicated synthetic test patient after the check",
    "steps":[
      {"method":"POST","url":"http://service:8080/test-session","headers":{"Content-Type":"application/json"},"body":"{\"user\":\"synthetic-health\"}","expected_status":201},
      {"url":"http://service:8080/test-session","expected_status":200,"body_contains":"synthetic-health"}
    ],
    "cleanup_steps":[
      {"method":"DELETE","url":"http://service:8080/test-session","expected_status":204}
    ]
  }
]
```

Это пример контракта для специально поддерживаемого endpoint, а не универсальный сценарий каждого CTF-сервиса. Для меняющих запросов обязательно явное подтверждение безопасных тестовых данных и описание очистки. Cleanup выполняется также после провала основного шага; неуспешная очистка не даёт зелёный результат. Общий deadline ограничивает и cleanup, поэтому при недоступности сервиса Admin должен следовать указанной процедуре. Игровые флаги и реальные записи не используются в качестве тестовых данных.

## Политика, секреты и время

Настраиваются прогрев 1..300 секунд (по умолчанию 45), общий deadline проверок 1..300 (60), 1..10 попыток (1), интервал 1..30 (1), актуальность результата 1..3600 секунд (30). Проверки выполняются при Start/Restart/Deploy/Rollback/Recover. После TTL отображается `stale`; периодического функционального опроса вне операций нет.

Полный новый набор заменяет старый после Admin-подтверждения адресов/данных/очистки. `[]` отключает локальные проверки. Request inputs целиком хранятся в неизменяемой приватной версии Vault: URL с query, headers/body и ожидания ответа не возвращаются GET API. В summary доступны ID, вид проверки, origin, число шагов и timeout. При редактировании задаётся полный набор заново; credentials не копируются обратно в браузер. Общий редактор диагностик учитывает эти значения для redaction. Request/response contents не включаются в результат проверки или аудит.

Health policy имеет свою CAS revision и привязку к текущей доверенной регистрации. Изменение проверок запрещено, пока существуют queued/running/unresolved операции этого сервиса. Revision входит в operation plan: замена после Preview делает старое подтверждение недействительным до новой проверки. Исторический check observation сохраняет revision применённой политики.

Адрес должен быть доступен из namespace executor. В bridge-профиле `127.0.0.1` — executor, а не host-loopback сервиса. Панель не меняет port bindings ради проверки. Если маршрута нет, локальная проверка остаётся не настроенной/недоступной.

## Ручная проверка

Admin и Defender могут сохранить отдельный положительный/отрицательный результат с комментарием и TTL 1..3600 секунд. Backend назначает автора из серверной сессии и связывает запись с текущими release ID, runtime state sequence и digest фактических контейнеров, включая Docker StartedAt. Повторный запуск того же container ID, переключение, изменение наблюдаемого состояния или истечение TTL делают подтверждение устаревшим. Старая открытая форма отклоняется при изменившемся runtime. Положительный результат требует запущенных контейнеров и воспроизводимого релиза; принятие внешнего drift как непроверенной recovery point не подтверждает исправность старого релиза.

Ручная проверка не заменяет автоматическую functional proof, не делает релиз `locally_verified` для ротации и не обозначает успешный checker. Автор, время, comment и provenance доступны отдельно. В комментарии нельзя размещать пароли и игровые секреты.

## API и проверки реализации

- `GET /api/services/{id}/checks` — summary, settings, revision, текущая runtime identity и до 10 manual confirmations.
- `POST /api/services/{id}/checks` — Admin, CSRF, `expected_revision`, `confirmed`, полный `policy`.
- `POST /api/services/{id}/checks/manual` — Admin/Defender, CSRF, ожидаемые release/sequence/runtime digest, TTL/result/comment.

Внутренние Unix-маршруты `/v1/services/{id}/checks[/manual]` типизированы теми же DTO. Viewer не может изменять проверки или оставлять подтверждение. Аудит содержит идентификаторы, действия и результат, без bodies/headers/token.

Race-тесты проверяют TCP success/closed port, legacy GET, oversized response, redirect refusal, cookies между HTTP-шагами, cleanup после ошибки, retries/overall deadline/TTL, Vault-only inputs, CAS и invalidated Preview, queued busy guard, авторство, runtime restart/TTL invalidation, RBAC и CSRF. Они не заменяют проверку реальных endpoint из production bridge executor.
