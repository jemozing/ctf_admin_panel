# Публичная сводка проверок

Подготовлено 30 октября 2026 года. Это обезличенная сводка ранее выполненных проверок и индекс исторических артефактов. Подготовка к публикации не включает новые runtime-испытания.

**Полная приёмка MVP не завершена (`mvp_accepted=false`).** В A01–A39 остаются 19 критериев, подтверждённых в описанных ограниченных профилях, и 20 частичных. Испытания целевого `competition-4g` (Linux/amd64, 4 vCPU, 4 GiB RAM, диск 40 GiB) и VM-проверки отложены. [Полная матрица и границы результатов](../../../docs/progress.md#матрица-a01a39), [Proxy P01–P16](../../../docs/http-proxy-waf-plan.md), [Capture C01–C10](../../../docs/packet-capture-plan.md).

В Git доступны этот индекс, [машинная сводка](public-summary.json), исходники тестов и [инструкции повторения](../../../docs/testing.md). Сырые JSON-отчёты, журналы, PCAP, cookie jars и снимки экрана сохранены локально и исключены из публикации. Исторические имена ниже нужны для сопоставления со ссылками документации; они ведут на описания, а не на скачивание исходных артефактов. Точные приватные diagnostics, image inventories и данные игровых записей здесь не воспроизводятся.

## Границы подтверждений

<a id="native-systemd-ci"></a>

### Нативная поставка и systemd на Linux/amd64 — 2 ноября 2026 года

В [GitHub Actions](https://github.com/jemozing/ctf_admin_panel/actions/runs/41495581883) для HEAD ветки [`afd315804271a01e1311135f3352c8b1894ee240`](https://github.com/jemozing/ctf_admin_panel/commit/afd315804271a01e1311135f3352c8b1894ee240) успешно собраны пакеты Linux amd64/arm64 и пройден настоящий Linux/amd64 systemd lifecycle на свежем ephemeral runner. В Pull Request checkout может использовать merge ref с `main`, поэтому HEAD запуска не подменяет `source.commit` в manifest пакета. Job публикации пропущен: этот прогон не создавал GitHub Release.

Пройдены 23 runtime-проверки: настоящая установка и версия бинарника, непривилегированный Admin bootstrap и вход, UID/capabilities и закрытые файлы, Unix socket/peer IPC, API выбора папок и Compose-подсказка, host-метрики с проверенным procfs-источником. Остановка executor не останавливает dashboard; после возврата executor прежний dashboard снова связывается с ним. Upgrade сохранил конфигурацию, dashboard DB и администратора; вход и обе службы работают после обновления. Собственные службы завершены после smoke.

Локально также пройдены frontend build, 48 helper-тестов и 193 packaging tests. [Матрица N01–N06](../../../docs/progress.md#нативная-поставка-и-сборка-в-actions--2-ноября), [исходник smoke](../native_systemd_smoke.py). Сырой отчёт сохранён локально и не публикуется.

Docker запросы были только read-only preflight, игровые контейнеры не создавались, пользовательская VM не затрагивалась. ARM64 подтверждён cross-build, но его настоящий systemd runtime не проверен. Этот smoke не заменяет Deploy/Rollback игровых сервисов, соревновательную нагрузку или открытую A/P/C-приёмку.

<a id="git-probe-local"></a>

### Проверка Git и выбор ветки — 2 ноября 2026 года

Реализована read-only проверка введённых URL/credentials и опубликованного ref. Пройдены полный Go race-прогон и финальные sourcegit race tests, vet затронутых пакетов, frontend/manager build, 48 frontend helpers и 157 packaging tests. В sourcegit добавлены 12 тестовых функций с реальным локальным TLS Git transport: refs, ошибки auth/TLS, redirect, cancellation, limits и отсутствие objects/credentials leaks. Executor scope/readonly покрыт 6 функциями; transport/dashboard проверяют Admin, CSRF, strict JSON и удержание приватных refs после отзыва сессии/роли или сбоя аудита.

UI прошёл 31 Chromium check и 8 process checks через настоящий dashboard с синтетическим Unix executor, без browser API interception: выбор ветки, разные статусы ref, ошибки доступа/retry и поздние ответы после редактирования/закрытия. Это не live GitHub. Production probe публичного GitHub был отклонён до соединения из-за restricted DNS; успешный live GitHub/GitLab check не заявляется. [Повторение](../../../docs/testing.md#проверка-git-и-выбор-ветки).

VM, Docker и игровые сервисы не использовались. Сырые отчёты остаются локально; общая Linux/CTF приёмка открыта.

<a id="directory-picker-local"></a>

### GUI выбора папки — 2 ноября 2026 года

Добавлен ограниченный просмотр папок Docker-хоста для Admin. Восемь новых Go backend-тестов с race проверяют границы discovery roots, символические ссылки и конкурентную подмену, имена, лимиты, FIFO и отмену. Dashboard/Unix API проверяют RBAC, CSRF и строгий JSON. Полный Go race-прогон и vet затронутых пакетов пройдены. Четыре новых helper-теста входят в 42 frontend checks; frontend и manager собраны, 157 packaging checks пройдены.

Реальный Chromium через отдельные dashboard/executor прошёл 32 browser checks и 5 process checks без API mocks: навигация, Compose-подсказка, выбор, отмена, ручной ввод, ошибка/повтор, исключение ссылок и узкий экран. Все временные процессы завершены. Сырые отчёты остаются локально; [скрипт повторения](../directory_picker_process_smoke.py) и [инструкция](../../../docs/testing.md#gui-выбора-папки-без-docker) опубликованы.

Docker endpoint в fixture — отсутствующий временный Unix socket; VM и контейнеры не использовались, сервисы не регистрировались. Linux/CTF приёмка и прежние A/P/C статусы остаются открытыми.

<a id="mvp-local"></a>

### Исторические MVP-проверки

Синтетические Compose/workflow/fault/storage/backup сценарии и адаптированные браузерные циклы пяти SibirCTF выполнены в указанных в документации профилях. Это преимущественно Linux/arm64 OrbStack; отдельные amd64 запуски использовали эмуляцию.

- Старые артефакты предшествуют части исправлений и новым модулям.
- Пятиминутная нагрузка на общей VM не подтверждает competition-4g и часовой soak.

<a id="native-linux"></a>

### Linux/amd64 VM

Подтверждены Compose, 13 workflow checks, backup/restore, native race/vet и четыре полных цикла BioGuard/ncdex/CyberBank/neuroLinks с сохранением данных.

- Финальный итог EyeSee неизвестен после потери SSH.
- Короткий load preflight не прошёл; повторились kernel stalls.
- Пятиминутный benchmark, часовой soak и новая аварийная серия не завершены.
- Текущая доступность VM и финальный возврат временного DNS не подтверждены.

<a id="proxy-local"></a>

### HTTP Proxy, TLS и WAF

Локально проверены HTTP/TLS процессы, маршрутизация/трафик, rate limits и bans; реализованы групповой перенос/возврат портов и explicit HTTPS/2 termination.

- Локальные unit/process проверки не заменяют реальный Compose cutover и checker.
- P01–P16 и совместная вместимость 4 GiB на целевом хосте открыты.

<a id="traffic-local"></a>

### Пакеты, потоки и gRPC

Разработка 10.0–10.4 завершена в bounded профилях: PCAP, TCP/UDP, HTTP2/gRPC/descriptors и интерфейс анализа. Финальные локальные API/process/browser проверки и Linux cross-build прошли.

- Live AF_PACKET, реальные NAT/bridge/veth/checker и CPU/RAM/drop rate не приняты.
- Этап 10.5/C10 и целевая Linux/Compose/CTF приёмка отложены.
- Cross-build не является запуском на Linux.

## Открытая приёмка

Требуются стабильный Linux/amd64 стенд, итог EyeSee и общий postflight пяти сервисов, нагрузка и часовой soak на 4 GiB, аварийные проверки daemon/registry/fsync/power loss, а также целевые Compose/CTF проверки Proxy/WAF и живого захвата. Исторические успешные smoke и локальные cross-build не повышают эти статусы. Причина зависаний VM не установлена окончательно; влияние одной только нагрузки приложения не доказано.

## Индекс исторических артефактов

Индекс сохраняет названия артефактов, которые упоминаются в документации, включая неудачные и промежуточные попытки. Запись в индексе сама по себе не означает PASS. Результат и применимые ограничения указаны в связанных матрицах и разделах выше.

<a id="report-apply-efbig-linux-2026-10-20-json"></a>

### `apply-efbig-linux-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-compose-metrics-smoke-2026-10-19-json"></a>

### `compose-metrics-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-compose-smoke-2026-10-19-json"></a>

### `compose-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-compose-smoke-2026-10-20-json"></a>

### `compose-smoke-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-container-release-amd64-emulated-2026-10-19-json"></a>

### `container-release-amd64-emulated-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-container-release-smoke-2026-10-19-json"></a>

### `container-release-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-executor-peer-linux-2026-10-19-json"></a>

### `executor-peer-linux-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-fault-multi-component-2026-10-20-json"></a>

### `fault-multi-component-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-fault-release-smoke-2026-10-19-json"></a>

### `fault-release-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-fault-release-smoke-2026-10-20-json"></a>

### `fault-release-smoke-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-fixture-smoke-2026-10-19-json"></a>

### `fixture-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-git-bundled-source-limits-2026-10-19-json"></a>

### `git-bundled-source-limits-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-http-proxy-cutover-tls-2026-10-30-json"></a>

### `http-proxy-cutover-tls-2026-10-30.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [HTTP Proxy, TLS и WAF](#proxy-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-http-proxy-group-cutover-2026-10-30-json"></a>

### `http-proxy-group-cutover-2026-10-30.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [HTTP Proxy, TLS и WAF](#proxy-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-http-proxy-process-smoke-2026-10-30-json"></a>

### `http-proxy-process-smoke-2026-10-30.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [HTTP Proxy, TLS и WAF](#proxy-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-http-proxy-prototype-2026-10-30-json"></a>

### `http-proxy-prototype-2026-10-30.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [HTTP Proxy, TLS и WAF](#proxy-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-http-proxy-tls-process-smoke-2026-10-30-json"></a>

### `http-proxy-tls-process-smoke-2026-10-30.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [HTTP Proxy, TLS и WAF](#proxy-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-journal-enospc-2026-10-20-json"></a>

### `journal-enospc-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-linux-backup-maintenance-2026-10-19-json"></a>

### `linux-backup-maintenance-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-linux-git-isolation-2026-10-19-json"></a>

### `linux-git-isolation-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-linux-mount-boundary-regression-2026-10-19-json"></a>

### `linux-mount-boundary-regression-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-mvp-acceptance-2026-10-20-json"></a>

### `mvp-acceptance-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-mvp-functionality-smoke-2026-10-19-json"></a>

### `mvp-functionality-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-mvp-pipeline-negatives-smoke-2026-10-20-json"></a>

### `mvp-pipeline-negatives-smoke-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-mvp-workflows-smoke-2026-10-20-json"></a>

### `mvp-workflows-smoke-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-bioguard-data-postflight-2026-10-29-json"></a>

### `native-bioguard-data-postflight-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-compose-smoke-2026-10-29-json"></a>

### `native-compose-smoke-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-current-acceptance-2026-10-29-json"></a>

### `native-current-acceptance-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-fetch-dns-diagnostic-2026-10-29-json"></a>

### `native-fetch-dns-diagnostic-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-five-sibir-cycles-attempt1-2026-10-29-json"></a>

### `native-five-sibir-cycles-attempt1-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-five-sibir-review-deployment-2026-10-29-json"></a>

### `native-five-sibir-review-deployment-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-five-sibir-review-ready-2026-10-29-json"></a>

### `native-five-sibir-review-ready-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-go-race-vet-2026-10-29-json"></a>

### `native-go-race-vet-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-go-race-vet-attempt1-2026-10-29-json"></a>

### `native-go-race-vet-attempt1-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-kernel-stalls-acceptance-2026-10-29-json"></a>

### `native-kernel-stalls-acceptance-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-mvp-acceptance-2026-10-29-json"></a>

### `native-mvp-acceptance-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-mvp-workflows-2026-10-29-json"></a>

### `native-mvp-workflows-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-panel-load-preflight-attempt1-2026-10-29-json"></a>

### `native-panel-load-preflight-attempt1-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-preacceptance-backup-2026-10-29-json"></a>

### `native-preacceptance-backup-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-unprepared-host-2026-10-29-json"></a>

### `native-unprepared-host-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-vbox-full-log-review-2026-10-29-json"></a>

### `native-vbox-full-log-review-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-vm-inventory-2026-10-29-json"></a>

### `native-vm-inventory-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-native-vm-kernel-stability-2026-10-29-json"></a>

### `native-vm-kernel-stability-2026-10-29.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Linux/amd64 VM](#native-linux), [подробная история и матрица](../../../docs/progress.md).

<a id="report-observation-load-2026-10-19-json"></a>

### `observation-load-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-observation-load-2026-10-20-json"></a>

### `observation-load-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-packet-capture-local-2026-10-30-json"></a>

### `packet-capture-local-2026-10-30.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Пакеты, потоки и gRPC](#traffic-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-packet-capture-process-smoke-current-2026-10-30-json"></a>

### `packet-capture-process-smoke-current-2026-10-30.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Пакеты, потоки и gRPC](#traffic-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-packet-panel-process-smoke-final-2026-10-30-json"></a>

### `packet-panel-process-smoke-final-2026-10-30.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Пакеты, потоки и gRPC](#traffic-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-preview-fixed-images-2026-10-20-json"></a>

### `preview-fixed-images-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-preview-inactive-db-integrity-2026-10-20-json"></a>

### `preview-inactive-db-integrity-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-registration-smoke-2026-10-19-json"></a>

### `registration-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-release-storage-backup-smoke-2026-10-19-json"></a>

### `release-storage-backup-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-runtime-fixtures-smoke-2026-10-19-json"></a>

### `runtime-fixtures-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-runtime-registration-smoke-2026-10-19-json"></a>

### `runtime-registration-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-screenshots-sibir-bioguard-jpg"></a>

### `screenshots/sibir-bioguard-*.jpg`

Исторические локальные снимки браузерного сценария. Вложения не опубликованы; контекст: [реальные сервисы](../../../docs/real-services.md).

<a id="report-security-acceptance-2026-10-20-json"></a>

### `security-acceptance-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-sibir-bank-manifest-diff-2026-10-19-json"></a>

### `sibir-bank-manifest-diff-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-sibir-bank-web-cycle-2026-10-19-json"></a>

### `sibir-bank-web-cycle-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-sibir-bioguard-manifest-diff-2026-10-19-json"></a>

### `sibir-bioguard-manifest-diff-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-sibir-bioguard-web-cycle-2026-10-19-json"></a>

### `sibir-bioguard-web-cycle-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-sibir-eyesee-web-cycle-2026-10-19-json"></a>

### `sibir-eyesee-web-cycle-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-sibir-four-web-cycles-2026-10-19-json"></a>

### `sibir-four-web-cycles-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-sibir-ncdex-web-cycle-2026-10-19-json"></a>

### `sibir-ncdex-web-cycle-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-sibir-neli234-web-cycle-2026-10-19-json"></a>

### `sibir-neli234-web-cycle-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-sqlite-wal-lock-safety-2026-10-20-json"></a>

### `sqlite-wal-lock-safety-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-storage-pressure-2026-10-19-json"></a>

### `storage-pressure-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-traffic-development-2026-10-30-json"></a>

### `traffic-development-2026-10-30.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Пакеты, потоки и gRPC](#traffic-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-unprepared-host-2026-10-20-json"></a>

### `unprepared-host-2026-10-20.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-web-registration-browser-2026-10-19-json"></a>

### `web-registration-browser-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

<a id="report-web-registration-git-smoke-2026-10-19-json"></a>

### `web-registration-git-smoke-2026-10-19.json`

Исходный артефакт сохранён локально. Публичный контекст и ограничения: [Исторические MVP-проверки](#mvp-local), [подробная история и матрица](../../../docs/progress.md).

## Writable code binds: локальные проверки

<a id="writable-code-binds-local"></a>

3 ноября: opt-in конкретных disposable bind-монтов, пересчёт управляемых путей и явное согласие GUI. Общий Go race/vet, сборки, 53 frontend helpers, 193 packaging и 21 Chromium check прошли. Browser использует синтетический API на loopback; executor fixture выполняет настоящие snapshots/MaterializeBuild/Apply/обратный Apply, без Docker lifecycle. Runtime DB/uploads/.env исключены. Реальные Compose/CTF-проверки общего writable root bind остаются открытыми; подробности — [W01–W06](../../../docs/progress.md).
