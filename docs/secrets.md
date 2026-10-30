# Версии секретов и локальное обслуживание

Executor импортирует environment и file-backed secrets/configs в приватный vault. Релиз хранит ссылки на точные версии. Изменение исходного `.env` не переписывает уже подготовленный релиз.

Команды `secrets` выполняются локальным администратором с bootstrap executor и не обращаются к Docker API. Перед обслуживанием остановите executor, предварительно завершив его задания и восстановление. Эксклюзивный maintenance lock не допускает одновременную работу executor, второго secret CLI или backup. Наличие queued/running/interrupted/requires_recovery задания блокирует изменение секретов даже после остановки процесса. Dashboard и игровые приложения останавливать для этой процедуры не требуется.

```sh
docker compose --env-file /srv/ctf-manager/config/compose.env stop executor
sudo ./bin/ctf-manager --config /srv/ctf-manager/config/executor.json secrets list
sudo ./bin/ctf-manager --config /srv/ctf-manager/config/executor.json secrets inspect \
  --secret-id secret-example --version VERSION
```

Каталог показывает только ID, размер, признаки отзыва/удаления и зависимости: текущие политики сервисов, immutable конфигурации, релизы, материализованные file inputs, Git credentials и политики проверок. Значения секретов не возвращаются. Исторические зависимости остаются видны после retirement релиза и удаления версии.

## Новая версия

```sh
sudo ./bin/ctf-manager --config /srv/ctf-manager/config/executor.json secrets import \
  --secret-id secret-example --file /root/new-secret.private
```

Допускается `--stdin` вместо `--file`. Вход ограничен 1 MiB; байты сохраняются точно, включая конечный перевод строки. Файл должен принадлежать вызывающему UID, иметь права `0600` или строже и быть обычным файлом с одной ссылкой. Symlinks отвергаются. Значение не передаётся аргументом команды или через environment.

Импорт создаёт новую независимую версию и выводит её ссылку вместе с предыдущими версиями и зависимостями. Он не активирует её в существующей доверенной конфигурации и не меняет старые релизы. Ввод новых runtime env/file inputs в работу требует отдельной повторной регистрации и утверждения политики; обычный Deploy не расширяет её автоматически.

## Отзыв и удаление

Сначала выполните команду без `--confirm`. CLI покажет зависимые объекты и `confirmation_digest`, затем завершится с требованием подтверждения. Повторите ту же команду, добавив показанный digest:

```sh
sudo ./bin/ctf-manager --config /srv/ctf-manager/config/executor.json secrets revoke \
  --secret-id secret-example --version VERSION
sudo ./bin/ctf-manager --config /srv/ctf-manager/config/executor.json secrets revoke \
  --secret-id secret-example --version VERSION --confirm sha256:DIGEST
```

Подтверждение связывает действие, точную версию, её состояние и список зависимостей. Изменившийся план требует повторного просмотра. Отзыв делает эту версию недоступной для новых Build/Deploy/Rollback, включая исторические релизы; уже запущенные контейнеры продолжают использовать ранее переданные им значения. Отзыв не заменяет secret rotation внутри приложения и не отзывает внешние токены у провайдера.

Удаление выполняется аналогично командой `secrets delete` и требует предварительного отзыва. Сначала сохраняется и синхронизируется tombstone, затем удаляется vault-файл и принадлежащие этой версии материализованные runtime inputs. Ссылки в immutable релизах сохраняются и объясняют недоступность артефакта. Активный процесс может удерживать ранее открытый файл или значение в памяти. Удаление файла не обещает физического стирания блоков диска, резервных копий или памяти приложения.

После обслуживания запустите executor:

```sh
docker compose --env-file /srv/ctf-manager/config/compose.env up -d executor
```

## Аудит и проверки

Изменения секретов и экспорт backup оставляют immutable `maintenance_audit` в БД executor: UTC, локальный UID, действие, режим, digest целевого идентификатора, request ID и результаты `started`/`succeeded`/`failed`. Значения, пути файлов и произвольные диагностические сообщения в этих событиях отсутствуют. Очищенный metadata export переносит только проверенные типизированные поля аудита. Если подтверждённое обслуживание не может записать аудит, CLI не сообщает успех.

Unit/race tests проверяют разделение версий, dependency plans, отказ без подтверждения, отзыв одной версии, tombstones, очистку собственных runtime inputs, блокировку незавершёнными заданиями и maintenance locks. Физическое secure erase и отзыв токена во внешнем Git-провайдере в этот механизм не входят.
