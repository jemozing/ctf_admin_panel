# neuroLinks 2-3-4 — браузерный цикл проверен

Источник: [SibirCTF/2025-cybersibir-service-neLi234](https://github.com/SibirCTF/2025-cybersibir-service-neLi234/tree/28d8a11498675233e87394e4d89956ad0938abfd), commit `28d8a11498675233e87394e4d89956ad0938abfd`, LICENSE MIT.

19.10.2026 сервис зарегистрирован через веб-мастер: путь проекта, классификация кода и данных, Git URL с точным commit, просмотр неизменяемого предложения и подтверждение Admin. Регистрация `service-9502046f3d926ca92d909f57357273fc`, proposal `proposal-b544d656112273e8df0c3e07e67b5cfa`. Git Fetch, Build, Deploy и Rollback запускались через панель. Подготовительный helper запускал отдельный исходный Compose-проект и обычные игровые TCP-запросы; операции регистрации и очереди он не отправляет.

Полный машиночитаемый результат с assertions, событиями и снимками браузера: [sibir-neli234-web-cycle-2026-10-19.json](../../integration/reports/sibir-neli234-web-cycle-2026-10-19.json). Проверка всех Git blobs: [sibir-neli234-manifest-diff-2026-10-19.json](../../integration/reports/sibir-neli234-manifest-diff-2026-10-19.json).

## Проверенный профиль

| Компонент | Роль | Состояние и обновление |
|---|---|---|
| `controller` | C++, собственный текстовый TCP 2340; единственный target Build/Deploy/Rollback | Относительный `messages.db` перенесён в named volume через `working_dir: /data`; root filesystem read-only |
| `neurolink` | Внутренний Go ELF amd64, TCP 8080; stateful dependency, роль database | Непрозрачный бинарник содержит SQLite `:memory:`. RAM-состояние сохраняется посредством исключения компонента из пересоздания |

Нативный Linux project directory: `/srv/ctf-manager-preview/services/sibir-neli234`, Compose project `ctfm-preview-sibir-neli234`, файл `ctfm.runtime.yaml`. Управляемый путь — весь `vuln-service`, kind `code`; Git subdirectory пустой. Оригинальные Dockerfiles, бинарник и схема БД сохранены. Исходный upstream Compose не используется: в нём SQLite находилась в `/app/messages.db` внутри writable layer без mounts.

Локальный профиль добавляет сохранение SQLite в `ctfm-preview-sibir-neli234_sqlite-data`, loopback-публикацию TCP на случайном порту, лимиты памяти/CPU/PID, `shm_size: 64m`, ротацию логов и socket-listen healthchecks. Controller собирается как Linux/arm64; поставляемый neurolink ELF работает как Linux/amd64 через эмуляцию OrbStack. Архитектуры выбираются при первоначальной подготовительной сборке, затем сохраняются точные image ID. Runtime-ключи `platform` и `tmpfs` удалены до регистрации, поскольку MVP пока отклоняет их при сверке runtime; `read_only: true` у controller сохранён. При подготовительном пересоздании только controller SQLite и исходные RAM-данные neurolink сохранились; это отражено в отчёте.

`neurolink` нельзя пересоздавать в этом профиле. Проверка файлов и FD после записи данных показала только бинарник в `/app`, без файлов БД; writable-layer delta содержит внедрённые OrbStack CA. Это согласуется с найденным `:memory:` и успешным чтением RAM-концептов, но не заменяет аудит отсутствующих исходников. Сохранность RAM при рестарте neurolink не проверялась и не гарантируется.

## Фактический результат

| Шаг | Результат |
|---|---|
| Веб-регистрация | Baseline импортирован автоматически; контейнеры, файлы, SQLite и volume не изменились |
| Первый Git Fetch | Безопасный отказ до mutation: `sqlite3.c` занимает 9 235 994 байта и превышал прежний предел 8 MiB; candidate не создан, активный сервис и данные сохранены |
| Исправление границы и повторный Fetch | Предел одного файла увеличен до 16 MiB при прежних 32 MiB на дерево и 64 MiB на репозиторий. Обновлён только executor; повторный Fetch успешен |
| Build | Настоящая сборка C++/bundled SQLite по неизменённому upstream Dockerfile; новый controller image `sha256:fd4d23d3c3b1e3756f71482568fe4413d969343523e8a08978b968e7129cc2e9` |
| Deploy | Применён Git-релиз `rel-1427117d4dde8a2c5d9dcc5b1624c0c0`; импортированная тестовая надпись в TCP-меню исчезла; исходные игровые записи доступны |
| Новые данные под Git-релизом | Обычным авторизованным протоколом добавлены ещё один SQLite thought и один RAM-концепт; свежий login прочитал исходные и новые записи |
| Rollback | Возвращён `rel-e603e91095b27ede640ffd635d329108` и точный исходный image `sha256:5433307acfbff34d99446fc0d62747f977c6c6355b4b0bccba02a71205064dba`; надпись восстановилась; исходные и новые данные сохранились |

Первый отказ Fetch сохранён в истории отдельно от успешной повторной попытки: всего шесть durable operations — snapshot, failed fetch, successful fetch, build, deploy, rollback. Исправление предела находится в [sourcegit/git.go](../../../internal/sourcegit/git.go); граничные проверки — [sourcegit/git_test.go](../../../internal/sourcegit/git_test.go). Подтверждение обновления только executor и результатов граничных тестов включено в JSON-отчёт.

Все 17 выбранных upstream blobs совпали со snapshot по SHA-256, размеру и mode, включая bundled SQLite и opaque binary. Наборы файлов и каталогов точны. Из 23 изменённых manifest entries 22 отличаются только метаданными GID 0→10001; единственное изменение содержимого — документированная надпись в `controller/src/server.cpp`. Это переход с импортированного локального baseline на точный upstream commit, а не сравнение двух upstream revisions.

После Deploy новая игровая запись изменила SHA-256 `messages.db` с `1c1789b1037bf44e5401a9485a6dde027481cab2bf3b73a0b506ce96ac1c7be6` на `062e455d1d05868938d65f84c7df017a9cebd29a9be86b9cbbb9346621356b50`. После Rollback сохранён именно второй файл, Users=1, Thoughts=2, прежняя схема, `PRAGMA quick_check=ok`, прежние name/mountpoint/CreatedAt volume. Таким образом Rollback вернул код и образ, сохранив новые игровые данные. Дополнительно свежий TCP login прочитал оба SQLite thought и оба RAM-концепта.

neurolink сохранил исходные container ID `cd509be63dcdf88067f2760c79f4860ae4c65a3019f482e8813993c141d05521`, image ID и StartedAt `2026-10-19T15:11:24.155468387Z` на всём цикле. Controller после отката healthy, endpoint `tcp://127.0.0.1:32858`; порт изменяется при пересоздании. Git-релиз оставлен доступным в панели.

## Границы проверки

Это успешный прогон адаптированного профиля обновления controller с непересоздаваемой stateful dependency. Он не подтверждает сохранность оригинального writable-layer layout, возможность обновления самого opaque neurolink или полную приёмку на native Linux/amd64. Panel readiness/functional checks не настроены: Docker healthchecks проверяют LISTEN, а независимый helper выполняет обычные registration/login/store/read по TCP. Organizer checker и exploits не запускались. Private GitLab, moving ref, offline registry и стабильный ingress в этом прогоне не проверялись.

Воспроизводимые helpers: [sibir_neli234_cycle.py](../../integration/sibir_neli234_cycle.py), [sibir_neli234_manifest.py](../../integration/sibir_neli234_manifest.py), [report_sibir_neli234_cycle.py](../../integration/report_sibir_neli234_cycle.py). Последний формирует отчёт только после проверки всех сохранённых наблюдений и обязательных снимков браузера; приватные пароли и игровые значения в отчёт не включаются.
