# Пакеты TCP/UDP, потоки и декодирование gRPC

Версия: 1.2. Дата: 30 октября 2026 года. Статус: **пакеты/PCAP, TCP-потоки, gRPC/descriptors и HTTP/2 TLS termination реализованы; Linux/VM-приёмка отложена**.

Документ дополняет ТЗ v2.12, §18.7 и этап 10. HTTP Proxy поддерживает HTTP/1.1 и отдельный opt-in `https2` для TLS HTTP/2/gRPC → h2c. Произвольный TCP/UDP forwarding не добавлен. Групповой перенос TCP-публикаций приложения не является поддержкой всех протоколов поверх TCP. Новое расширение добавляет наблюдение за существующим трафиком независимо от proxy; оно не меняет статусы A01–A39 и P01–P16.

## 1. Результат для пользователя

На странице «Трафик» появляются представления:

| Представление | Содержимое |
|---|---|
| HTTP | Существующий журнал обменов через HTTP Proxy: запросы, ответы, capture и решения HTTP WAF |
| Пакеты TCP/UDP | Время, сервис/компонент, интерфейс/точка наблюдения, направление, IP/порты, TCP flags, длина пакета и сохранённого префикса, hex/ASCII, классический PCAP; PCAPNG — последующее расширение |
| TCP-потоки | Два направления собранного потока байтов, границы захвата, retransmit/out-of-order, явные пропуски/усечение; TCP-пакет не выдаётся за полное прикладное сообщение |
| gRPC | После отдельного декодера: HTTP/2 stream, service/method, metadata, сообщения и trailers/status. Имена и типы protobuf-полей показываются при наличии подходящих descriptors |

Общие фильтры: все зарегистрированные сервисы / несколько сервисов / компонент, TCP/UDP, время, IP/CIDR, исходный/целевой порт, направление и поток. Live/pause/cursor pagination остаются ограниченными. UDP отображается датаграммами; удобная группировка по адресам не создаёт у UDP гарантий TCP-соединения.

Переключатель меняет представление наблюдений. Он не переносит порт, не включает новый proxy-протокол и не отключает WAF. Пассивный режим может наблюдать прямой TCP/gRPC-трафик EyeSee или neuroLinks без помещения его в неподдерживаемый HTTP Proxy, если выбранная точка захвата видит эти соединения.

## 2. Пассивный захват и границы доступа

Отдельный opt-in компонент `packet-capture` получает ограниченную копию пакетов на разрешённых точках Linux-хоста. В его тракте нет обязательной пересылки игровых соединений: остановка, переполнение очереди или ошибка декодера приводят к потерям наблюдения, а не к остановке сервиса.

Executor формирует типизированную карту только зарегистрированных сервисов: interface/namespace identity, адреса, TCP/UDP порты и ожидаемая runtime revision. Browser не передаёт произвольные shell-команды, путь интерфейса или свободный capture expression. Административный трафик панели, SSH, control/ingest и посторонних проектов исключён из предлагаемой конфигурации.

Захват не получает Docker socket, игровой filesystem, vault, Git credentials или основной IPC executor. На прототипе проверяются минимальные Linux capabilities для конкретного backend захвата; `privileged` и `NET_ADMIN` автоматически не включаются. Недоверенные декодеры работают отдельно от capture capabilities, без доступа к секретам и без возможности выполнять код из PCAP/descriptor.

Полная карта должна учитывать Docker NAT, bridge/veth/loopback, исходные/private публикации после cutover и обе стороны proxy. Реализованы до 8 проверенных Docker bridge-сетей компонента, veth-membership точки и host-publication альтернативы. Для одного target выбирается одна canonical leg: bridge/veth либо публикации хоста. Host leg предлагается только при единственной однозначной Docker-сети; произвольные до/после NAT tuple не склеиваются. Каждая запись содержит provenance. Один пакет, замеченный в нескольких точках, не должен незаметно удваивать счётчики; неоднозначная привязка отмечается как unknown/ambiguous, без произвольного назначения сервису. Смена контейнеров/портов требует свежей карты и новой подтверждённой ревизии, старые записи не переименовываются задним числом. Несколько точек могут видеть одно межсервисное соединение: исходные packet observations сохраняются, одинаковые TCP byte ranges объединяются при reassembly с provenance. Для UDP содержимое не используется как доказательство дубликата.

Для перенаправления произвольного TCP/UDP впоследствии нужен отдельный L4 proxy-профиль. Для одного просмотра пакетов такой перенос не требуется и в этап 10 автоматически не включается.

## 3. gRPC и шифрование

gRPC обычно передаёт framed-сообщения через HTTP/2. Удобный просмотр требует восстановления TCP-потока, разбора HTTP/2 с независимыми streams и затем gRPC framing. Разрывы захвата, середина уже открытого соединения, ограничения HPACK и сжатие могут сделать декодирование неполным; это показывается явно.

Без `.proto`/descriptor set доступен raw payload и, где возможно, ограниченное структурное представление. Человекочитаемые protobuf имена/типы не угадываются. Admin может явно подключить immutable descriptor set, привязанный к сервису/версии; server reflection и любые RPC к игре не вызываются автоматически.

TLS-пакеты можно сохранить и отобразить, но их payload остаётся шифрованным. Чтение содержимого допускается только в явно поддержанной точке termination либо с отдельно предоставленными session secrets. Наличие сертификата/закрытого ключа сервера само по себе не гарантирует расшифровку современного TLS. Профиль `https1` не меняется от включения packet capture: HTTP/2 termination включается отдельным выбором `https2`.

Первый gRPC decoder работает с plaintext HTTP/2; для TLS visibility реализован отдельный профиль HTTP/2 termination. Keylogs/session secrets, passthrough decryption и повторное TLS к upstream не включены. Секреты TLS не попадают в обычный PCAP/export, аудит или браузер по умолчанию.

## 4. Данные, ресурсы и WAF

Начальная настройка — ограниченный префикс пакета и/или метаданные; полный payload включается явно Admin. Нужны отдельные квоты и ротация PCAP, пределы ring buffer, snaplen, packet rate обработки, числа потоков, байтов reassembly, TTL и времени декодирования. Отдельно учитываются незавершённые сегменты, экспорты и временные файлы. Обязательны счётчики captured/dropped/truncated, collector epoch и явная неполнота. Численные caps определяются прототипом; «весь трафик за час» при любой нагрузке не обещается.

Raw PCAP нельзя объявлять автоматически очищенным от флагов/паролей как HTTP JSON. Payload, raw streams и PCAP export требуют sensitive access с повторной проверкой прав; изменение capture policy — Admin. Экспорт ограничен фильтром, временем и размером; просмотр и экспорт аудируются без payload. Метаданные предоставляются отдельно от байтов. Нагрузка модуля учитывается сверх proxy/recorder/dashboard/executor на `competition-4g`.

Пассивный захват не блокирует пакеты. Текущий HTTP WAF продолжает считать HTTP-запросы только на своих маршрутах. TCP connection/byte limits и UDP datagram limits — отдельный последующий enforcement-профиль; они не выдаются за request-rate WAF произвольного протокола.

## 5. Этапы и отдельная матрица

| Этап | Результат |
|---|---|
| 10.0 | Linux capture prototype, контракт карты сервисов/NAT, минимальные права и измеренный ресурсный бюджет |
| 10.1 | Представление пакетов, фильтры сервисов/протоколов, bounded ring/ротация и защищённый экспорт PCAP |
| 10.2 | Ограниченная TCP reassembly, двунаправленные потоки, gaps/out-of-order/retransmit и UDP datagrams |
| 10.3 | Plaintext HTTP/2/gRPC decoder и явное подключение descriptors |
| 10.4 | Отдельный профиль TLS visibility; приватные session secrets либо проверенная HTTP/2 termination |
| 10.5 | Изоляция, отказы, нагрузка и совместимость с реальными игровыми checker |

Реализация этапа 10.1 проверяется отдельно от дальнейших декодеров. VM не использовалась по указанию пользователя. Локальный отчёт: [packet-capture-local-2026-10-30.json](../tests/integration/reports/README.md#report-packet-capture-local-2026-10-30-json). Он фиксирует точный состав исходников/бинарников и ограничения свидетельств.

| ID | Приёмочный результат | Статус и локальные свидетельства |
|---|---|---|
| C01 | TCP и UDP нескольких сервисов видны без переноса портов и вмешательства в соединения | **Частично.** Реализован Linux AF_PACKET; injected Ethernet IPv4/IPv6 TCP/UDP проходят через настоящий parser → queue → SQLite → PCAP. На macOS живой AF_PACKET недоступен; реальный Linux/Compose и checker ещё не проверены |
| C02 | Фильтры/карта Docker/NAT корректны до и после Deploy/cutover; дубли и неоднозначность явны | **Частично, разработка текущих профилей завершена.** Multi-bridge, exact interface/index, verified bridge-member veth, host-publication/lo альтернативы и защищённые host ports; canonical-leg selection, mapped port, version pin и TTL проверены локально. TCP ranges объединяются с сохранением наблюдений/потерь; UDP остаются отдельными. Реальная NIC/NAT/bridge и overlap-network приёмка на Linux открыта |
| C03 | Hex/ASCII и PCAP содержат ожидаемые bytes; snaplen, rotation, квоты и export bounds соблюдены | **Локально пройдено для текущего профиля.** Точные binary bytes/PCAP headers, metadata-only incl_len=0, snaplen, IPv4/IPv6, квоты/retention/reserve, курсоры/gaps и пределы экспорта покрыты Go race и отдельными процессами. Внешний Wireshark/tcpdump и реальные NIC ещё не проверены |
| C04 | TCP stream корректен при retransmit/out-of-order/обрывах; пропуски не скрываются, UDP не теряет границы датаграмм | **Локально пройдено, этап 10.2 реализован.** SYN/FIN/RST, sequence wrap, reuse, reordering/overlap/conflict/gaps, missing prefix, byte/memory/window/timeout budgets и UDP проверены pure/race/fuzz и реальными archive/API процессами. UI показывает два направления, provenance и известную неполноту |
| C05 | Plaintext gRPC: unary/streaming, несколько HTTP/2 streams, metadata/messages/trailers; descriptors привязаны явно | **Локально пройдено, этап 10.3 реализован.** Bounded HPACK/frames, multiplexed unary/streaming, gzip, status/trailers и descriptor-pinned protobuf JSON; legacy/mixed/unbound/conflicting input не получает ложные имена. Реальный игровой checker остаётся в C10 |
| C06 | TLS обозначен шифрованным; расшифровка только по принятому отдельному профилю без утечки session secrets | **Локально пройдено для выбранного профиля 10.4.** Опт-in `https2` TLS1.2+/ALPNh2 → loopback h2c; trusted cert/SNI, streaming/cancel, LKG/restart, explicit raw capture и decoder после termination проверены. TLS wire payload без termination остаётся opaque. Keylog/passthrough decryption не реализуются этим профилем |
| C07 | RBAC/sensitive access/отзыв прав/аудит защищают payload, descriptors, configuration и export | **Локально пройдено для packets/PCAP/flows/decoder/descriptors/config.** Viewer metadata, sensitive bytes/export, Admin preview/confirm, actor injection, strict JSON, Origin/CSRF, отказ при отзыве сессии во время RPC и при сбое аудита. Descriptors preview/digest/actor/TTL/quota/delete/blob integrity и in-flight revocation проверены |
| C08 | Отказ capture/decoder/storage и переполнение очередей не останавливают игровой трафик | **Частично.** Bounded receive queue/PPS, slow/failing sink, reserve/write failure, lease expiry/pause, SIGKILL/restart архива проверены локально. Actual capture остаётся пассивным; влияния на реальные игровые соединения и checker пока не измеряли |
| C09 | Нет доступа к Docker/vault/game mounts/основному IPC, административный трафик исключён | **Частично.** Private exact container endpoints, immutable interface boundary, независимые control/ingest/read tokens и Unix reads; статические Compose/Dockerfile/bootstrap проверки проходят. Runtime isolation/CAP_NET_RAW на Linux ещё не приняты |
| C10 | CPU/RAM/диск/drop rate измерены на целевом профиле; checker/данные сохранены; общего обещания полной записи нет | **Отложено.** Опубликованы caps и неизвестность kernel drops; throughput/overhead и совместная вместимость `competition-4g` не измерены. A/P-матрицы остаются открытыми |

## 6. Реализованный профиль 10.1

- `ctfm-capture`: Linux AF_PACKET, Ethernet DLT 1, IPv4/IPv6 TCP/UDP, receive-only код без forwarding/injection/promisc. На иных ОС live-режим недоступен, offline fixtures явно обозначены. `ctfm-packets`: отдельная SQLite-база, без capabilities. Упаковка и команды: [packet-capture-deployment.md](packet-capture-deployment.md).
- Установка по умолчанию выключена. Root задаёт 1–8 точных observation interfaces в `capture.allowed_interfaces`, Admin выбирает только предложенные зарегистрированные application targets. До 8 bridge-сетей на компонент, private container IP, TCP/UDP ports из сверенного runtime EXPOSE/Compose. Можно выбрать canonical bridge, подтверждённый veth-member или frozen host-publication leg на одобренном интерфейсе. `host`/overlay network mode и произвольный BPF не добавлены. Host SSH/dashboard/control endpoints не предлагаются; игровой container port 22 сам по себе не запрещён.
- `preview → digest → confirm` фиксирует actor, installation authority, текущую конфигурацию файла без обновляемого lease, target IDs и applied revision. Подтверждённые версии append-only; публикация атомарна, отдельно видны desired/applied. Повторное подтверждение не создаёт вторую версию, publisher восстанавливает только подтверждённую публикацию. Лимиты: 512 ревизий / 1024 preview на эту итерацию.
- Worker с единственным ownership lock обновляет 10-секундный lease каждые 2 секунды только при свежем runtime и отсутствии queued/running операций. Перед Deploy/Rollback/Start/Stop/Restart/Recover, компенсацией и cutover наблюдение приостанавливается. При рестарте collector существующий enabled-файл не активируется: нужен заново опубликованный после старта файл со свежим lease, чтобы прежняя пауза не обходилась рестартом. Если control недоступен, перед изменением runtime ожидается истечение lease. Отказ executor прекращает наблюдение, не игровые соединения. После изменения ID/IP/interface нужен новый preview; простой restart тех же контейнеров может возобновить прежнюю карту. Сторонние изменения Docker обнаруживаются при проверке карты либо по истечении последнего lease, мгновенный внешний revoke не обещается.
- Начальный `snaplen=0` сохраняет только метаданные. Сохранение байтов Admin включает явно: 64–65 535 байт Ethernet-кадра, не «байт application payload». До 256 endpoint-привязок, 256 пакетов очереди, PPS 1–100 000 (UI по умолчанию 1000). Нет обещания полноты записи даже при этих настройках.
- Retention 60 минут, до 100 000 записей, физический SQLite+journal budget 256 MiB, логический 64 MiB и per-service 64 MiB, резерв места 1 GiB плюс journal. Ошибки записи/резерва останавливают новые записи до рестарта архива. Метаданные и bytes хранятся раздельно; неоднозначная запись учитывается в квоте каждого кандидата. Страница ≤200 записей и ≤2 MiB metadata, UI запрашивает 50; epoch/cursor gap показаны явно. Если выбран и source, и destination пакета, direction=`ambiguous`; фильтры ingress/egress не приписывают такому наблюдению единственное направление, для него есть отдельный фильтр.
- PCAP — little-endian classic Ethernet, до 10 000 пакетов / 8 MiB, меньший выбранный лимит также проверяется gateway. Экспорт в памяти, без временного файла, IPC ответ ограничен 12 MiB из-за base64. UI требует интервал до 60 минут и подтверждение экспорта, сервер ограничивает набор окном retention/фильтрами. Raw и PCAP требуют `sensitive_access`, повторной проверки сессии после RPC и успешного аудита до публикации bytes. Политика — только Admin. Никакой автоматической очистки секретов raw PCAP не обещается.
- Вкладка «Трафик → Пакеты»: фильтры сервисов/компонента/протокола/IP/CIDR/портов/времени/направления, live/pause, cursor pages, counters, safe hex/ASCII и скачивание PCAP. Live — ограниченный обновляемый список последних наблюдений, не гарантия показа каждого пакета. Потоки/gRPC доступны отдельной вкладкой. Kernel drops неизвестны и так обозначены; process counters относятся к текущему epoch.

Этапы 10.2–10.4 реализованы в bounded TCP/UDP, plaintext gRPC и explicit HTTP/2 termination профилях. [Контракт, использование и ограничения](traffic-analysis.md), [актуальный локальный отчёт](../tests/integration/reports/README.md#report-traffic-development-2026-10-30-json). Пассивный захват не меняет игровые порты/данные; активная termination требует отдельного proxy preview/cutover. Этап 10.5 и C10 остаются отложенной Linux/CTF-приёмкой.

Технические основания: [gRPC HTTP/2 protocol](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md), [gRPC reflection и descriptors](https://grpc.io/docs/guides/reflection/), [TCP reassembly](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection), [TLS visibility](https://wiki.wireshark.org/TLS).
