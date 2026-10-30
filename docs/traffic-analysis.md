# TCP-потоки, gRPC и TLS visibility

Дата: 30 октября 2026 года. Разработка этапов 10.2–10.4 завершена в описанных ниже профилях. Локальная приёмка отделена от живого Linux/Compose и `competition-4g`, которые пока отложены.

## В панели

В «Трафик» есть три вкладки: HTTP, Пакеты TCP/UDP, TCP-потоки/gRPC. Последняя группирует сохранённые пакеты в два направления TCP либо последовательность UDP-датаграмм. Фильтры выбирают сервисы, компонент, время, IP/CIDR, порты и направление. Фильтр отдельного порта/направления выбирает разговор, но не отбрасывает его обратную сторону перед восстановлением.

Список содержит только метаданные. Деталь с байтами и разбор gRPC доступны с `sensitive_access`. Видны SYN/FIN/RST, отсутствие начала, повторные передачи, порядок, пропуски, конфликты перекрытий, точки наблюдения, packet IDs и записанные версии кода. Одинаковые TCP-диапазоны с нескольких точек входят в восстановленные bytes один раз; исходные наблюдения и счётчики повторов сохраняются. UDP-датаграммы с одинаковым содержимым остаются отдельными: content hash не доказывает, что это один пакет.

Байты отображаются как текст/hex, не HTML. JSON protobuf показывается как текст и ограничивается в DOM. Live обновляет ограниченный список каждые пять секунд; при выборе детали используется зафиксированная граница архивного окна. При ротации/смене epoch либо достижении лимита показывается неполнота; при исчезновении выбранного потока данные не подменяются другим разговором.

## Восстановление TCP/UDP

Анализ выполняется по запросу в `ctfm-packets`, отдельно от процесса с `CAP_NET_RAW`. Persistent flow database и второй полный архив payload не создаются. Identity включает collector epoch, capture-policy revision, canonical IP/port tuple и incarnation; SYN/закрытие/idle разделяют повторное использование tuple. Несколько интерфейсов остаются в provenance одного TCP-разговора с одинаковым tuple. Разные tuple до/после NAT автоматически не объединяются.

Поддержаны порядок TCP sequence с wrap, retransmit, out-of-order, first-observed overlap и явные conflicts/gaps. Пропуски не заполняются нулями и не склеиваются. Наличие FIN/отсутствие известных gaps не доказывает полноту capture; kernel drops по-прежнему могут быть неизвестны. Конфликтующие bytes нельзя использовать как достоверный вход протокольного декодера.

| Предел | Значение |
|---|---|
| Сканируемое окно | До 10 000 пакетов / 8 MiB, включая metadata |
| Разговоры в одном анализе | До 256; metadata page до 200 / 2 MiB, UI запрашивает 50 |
| TCP bytes | До 1 MiB на направление, до 512 chunks |
| UDP | До 1024 датаграмм и 2 MiB на разговор |
| Packet IDs | До 10 000 на деталь; в chunk до 8 примеров; явная причина `chunk_provenance_truncated` |
| Параллельный анализ | 2 запроса; контекст анализа до 2 секунд |

При превышении предела видны `truncated` и причины. Для полного просмотра другого окна нужно сузить фильтр/интервал. Вкладка не обещает постоянную полную запись при любой нагрузке.

## Plaintext HTTP/2 и gRPC

Декодер принимает два непрерывных префикса TCP. Он определяет client direction по HTTP/2 preface, ведёт отдельные HPACK-контексты направлений, разбирает HEADERS/CONTINUATION/DATA/trailers/RST_STREAM и независимые streams. Unary, client/server/bidirectional streaming и gzip-сообщения проверены локально. Поддерживаются `grpc-status`, `grpc-message`, metadata и opaque binary messages.

При первом пропуске разбор останавливается; bytes после него не выдаются за продолжение HTTP/2. TLS определяется как зашифрованный протокол. Неизвестный preface, неподдерживаемое grpc-encoding, повреждённые frames, отсутствие финального status и ограничения ресурсов возвращают явные состояния. HTTP/2 server push, HTTP/3/QUIC, IP fragment reassembly и автоматическое раскрытие protobuf `Any` не поддержаны.

Пределы: input до 8 MiB, 128 HTTP/2 streams, 8192 frames, frame до 1 MiB, header block до 64 KiB, декодированные headers до 16 KiB/128 fields в блоке, HPACK table 4096 bytes. На RPC до 32 сообщений суммарно в обе стороны; сообщение до 1 MiB, общий бюджет messages/JSON/headers до 2 MiB. Gzip ограничен по результату; protobuf JSON до 1 MiB с предварительной оценкой узлов/размера до его выделения. Контекст/лимиты проверяются во время разбора.

## Descriptors

Admin с sensitive-доступом открывает «Descriptors» во вкладке потоков, выбирает зарегистрированный сервис, известный релиз и бинарный FileDescriptorSet (`.pb` / `.protoset`, с включёнными imports). Preview показывает SHA, pin релиза/исходников, файлы и методы. Подключение требует подтверждения digest в панели. Текст `.proto` не компилируется на сервере; RPC reflection, downloads/imports из сети и исполнение кода отсутствуют.

Executor сам выводит binding из зарегистрированного релиза. Browser не задаёт произвольные `binding`, source digest или actor. Подтверждённый descriptor immutable; ID учитывает содержимое и binding. При загрузке и подтверждении повторно проверяются blob digest и ID. Удаление descriptor не удаляет packets/flows; сообщения снова доступны как opaque bytes.

В захват записываются ReleaseID/SourceDigest конкретных endpoint. Для managed bind-кода текущий manifest сверяется с деревом релиза; при drift pins снимаются и нужен новый capture preview. Для image-кода это provenance утверждённого релиза и image ID, а не аттестация всех writable файлов контейнера. Внешнее изменение обнаруживается проверкой/lease, мгновенное обнаружение не обещается.

Схема применяется только при совпадении записанных pin. Legacy payload без pin, частично привязанный payload, конфликтующие версии и TCP overlaps не получают имён полей по текущему состоянию сервиса. Ошибка схемы не скрывает исходные bytes. Protobuf `Any` остаётся opaque; глобальные extensions/resolvers не используются.

До 2 MiB на descriptor, 32 записи / 8 MiB включая metadata. Draft живёт пять минут; TTL истекает и при точном равенстве deadline. Parser ограничивает wire/object budget до protobuf Unmarshal, затем число файлов/типов/полей/методов и глубину; одновременно допускаются два разбора. Descriptor rows находятся в той же private SQLite с физическим quota/reserve, отдельно от panel/vault.

## HTTPS/2 termination

В Proxy/WAF явно выбирается `HTTPS · HTTP/2 / gRPC → h2c` (`https2`). Нужны существующий immutable TLS-профиль, точный Host/SNI и проверенный plaintext HTTP/2 backend. Frontend использует TLS 1.2+ и ALPN `h2`; upstream — HTTP/2 prior knowledge по frozen literal-loopback HTTP origin. Старые `http1` / `https1` сохраняют прежние правила и HTTP/1.1 ALPN. Автоматический downgrade, TLS passthrough decryption, повторный TLS к backend и ACME не включены.

Перед подключением выполняется bounded preface/SETTINGS probe без application request. При переносе занятого порта проверяются текущие Docker publications до mutation; для новой private публикации handshake повторяется после создания. Non-loopback probe допускается только по точному literal IP текущего хоста и только из утверждённых executor bindings. Browser не передаёт origins.

Сохраняются streaming, multiplexing, отмена конкретного RPC, binary bodies и request/response trailers. WAF считает начала HTTP/RPC-запросов, а не protobuf messages внутри streaming RPC. Новый маршрут начинает observe-only; применение enforce требует обычного явного подтверждения checker. HTTP 429 не обещается как gRPC `RESOURCE_EXHAUSTED`.

Capture по умолчанию metadata-only. Режим `grpc_body` включается отдельно и помечает body `sensitive_raw`: до 64 KiB framed bytes на направление без обещания очистки игровых секретов. Header/trailer redaction продолжает действовать. Body другого/скрытого content type не публикуется как безопасный gRPC. В HTTP detail можно разобрать metadata/messages/status после termination.

Исторический HTTP exchange не содержит доверенного container-release pin: для него не подставляется текущий релиз и descriptor не применяется. Имена protobuf-полей для TLS-трафика доступны в version-pinned TCP-flow plaintext backend после termination. Этот путь требует включённого packet capture backend-сети. TLS session secrets/keylogs не сохраняются и не импортируются.

## API и безопасность

| Endpoint | Доступ |
|---|---|
| `GET /api/flows` | Аутентифицированный metadata-only список |
| `POST /api/flows/detail` | Sensitive: `{query,flow_id}` |
| `POST /api/flows/decode` | Sensitive: `{query,flow_id,descriptor_id?}` |
| `POST /api/traffic/{id}/decode` | Sensitive: gRPC terminated HTTP exchange |
| `GET /api/descriptors` | Sensitive: metadata подтверждённых схем, без blob/method contents |
| `POST /api/descriptors/preview` | Admin+sensitive: `{service_id,release_id?,data}` |
| `POST /api/descriptors/confirm` | Admin+sensitive: `{proposal_id,digest}` |
| `DELETE /api/descriptors/{id}` | Admin+sensitive |

Typed IPC/JSON отвергает unknown/duplicate/case-alias/actor fields. Descriptor upload допускает до 3 MiB JSON (2 MiB binary); остальные IPC budgets не расширяются. Каждое sensitive чтение/декодирование и изменение схемы аудируется без payload. Сессия/роль/sensitive access повторно проверяются после RPC и перед публикацией; неудачный audit удерживает результат. Frontend abort/permission guards очищают чувствительные результаты при смене scope/прав/ошибке.

У capture/recorder/decoder нет Docker socket, игровых mounts, vault и основного executor IPC. Сбой анализа/записи не становится условием forwarding. Runtime isolation, native NIC/bridge visibility и общий resource overhead всё ещё требуют Linux/Compose-приёмки.

Локальные результаты и точные source/binary digests: [traffic-development-2026-10-30.json](../tests/integration/reports/README.md#report-traffic-development-2026-10-30-json). Общая [матрица C01–C10](packet-capture-plan.md) не закрывает MVP A01–A39 и Proxy P01–P16 на целевой VM.
