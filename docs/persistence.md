# Журнал executor и очередь операций

`internal/store` хранит SQLite executor отдельно от web. Файл находится в защищённом каталоге executor, имеет mode `0600`, работает с `journal_mode=WAL`, `synchronous=FULL`, foreign keys и ограниченным busy timeout. Открытие существующего symlink, нерегулярного или доступного другим UID файла отклоняется. Владелец и защищённость всей иерархии служебных каталогов дополнительно проверяются при установке/preflight; SQLite сама не является границей против владельца хоста.

Все изменения выполняются через один `Store`; локальные Web/CLI используют один процесс executor. Интерфейсы не экспортируют SQL. Тестовые экземпляры используют локальную файловую систему; сетевые ФС не входят в профиль.

| Таблица | Назначение |
|---|---|
| `records` | Неизменяемые JSON-артефакты по `(kind,id)`, service ID и digest |
| `proposals`, `approvals` | Неизменяемая заявка с digest Service + normalized configuration digest и её локальное утверждение |
| `service_revisions`, `services` | Неизменяемая история политик и текущая утверждённая версия |
| `operations` | Долговечное состояние и глобальное соответствие `(initiator,idempotency_key)` входному digest |
| `locks` | Эксклюзивные ресурсы с владельцем operation ID |
| `events` | Append-only события с возрастающим sequence |

`PutImmutable` допускает повтор с тем же содержимым и service ID; изменение существующего объекта возвращает `ErrImmutable`. Триггеры запрещают UPDATE immutable records/proposals/policy history и UPDATE/DELETE журнала. Создание/утверждение новой политики не меняет старые релизы. Повторное утверждение старой заявки не возвращает текущую политику к старой ревизии.

`BeginOperation` атомарно создаёт queued operation, idempotency mapping и событие принятия. Входной hash вычисляет executor из авторизованных смысловых параметров; он исключает сгенерированные operation ID и время. Повтор возвращает исходную операцию, конфликт параметров — `ErrIdempotencyConflict`. Mapping сохраняется не меньше самой операции; удаление операций пока не реализовано.

`Acquire` берёт весь immutable resource set одной транзакцией. `service:<id>`, `compose:<project>`, `container:<id>`, `volume:<actual-name>` и shared keys сравниваются точно; `path:/absolute/path` дополнительно конфликтуют по вложенности компонентов пути. Это требует использовать канонические paths и фактические Docker identities, полученные из доверенной политики. CLI/HTTP payload не задаёт locks. Конфликт возвращает `BusyError` с ресурсом и владельцем; операция остаётся queued.

`UpdateOperation` использует compare-and-swap по прежнему `UpdatedAt`, требует увеличения времени, неизменяемой спецификации и допустимого перехода домена. Running/mutation разрешается только при владении всеми locks. Обновление состояния и событие фиксируются одной транзакцией. Движок обязан вызвать и дождаться успешного сохранения `BeginMutation` до изменения active state.

При запуске `MarkInterrupted` переводит running в interrupted, сохраняет recovery references и locks и пишет события. Он не вызывает Docker, не копирует файлы и не возобновляет Deploy. Дальнейшая сверка должна сравнить intent с фактическими контейнерами и файлами. `requires_recovery` и `interrupted` не освобождают ресурсы. `internal/jobs.Manager` объединяет submit/start/transition и освобождает locks только после подтверждённого terminal outcome.

Согласованное резервирование SQLite реализовано через VACUUM INTO под exclusive maintenance locks обеих state-директорий. Обычный экспорт реконструирует новые БД по whitelist без открытых секретов; protected full шифрует полный архив. После restore сессии отзываются, queued jobs и старые recovery approvals не воспроизводятся автоматически. Подробности — в [backup/restore](backup.md). Миграции будущих схем и retention самого журнала остаются отдельными задачами.

Проверки `internal/store`/`internal/jobs` охватывают конкурентные повторы, изменение параметров под тем же ключом, конфликт вложенных путей, CAS, невозможность запуска без locks, перезапуск с сохранённым recovery, неизменяемое утверждение и реальный режим WAL/FULL. Проверка обрыва питания и аварий на каждом Docker/filesystem шаге требует Linux-стенда последующих этапов.
