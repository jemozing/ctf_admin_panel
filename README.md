# CTF Service Manager

Веб-панель для управления сервисами своей команды на Attack/Defense CTF. Помогает обновлять код, собирать новые версии и откатывать изменения, сохраняя отдельно игровые данные.

[MIT](LICENSE) · [Разработка](https://github.com/jemozing/ctf_admin_panel/blob/main/CONTRIBUTING.md) · [Уязвимости](https://github.com/jemozing/ctf_admin_panel/blob/main/SECURITY.md)

## Что умеет

- Добавлять существующие Docker Compose-сервисы через панель: выбрать папку, проверить компоненты и подтвердить регистрацию.
- Получать исходники из GitHub/GitLab по HTTPS Git URL, собирать и применять версии, выполнять Rollback.
- Создавать снимки кода и резервные копии состояния панели, управлять ротацией и квотами.
- Показывать состояние контейнеров, логи и метрики с историей за 60 минут.
- Разделять доступ между Admin, Defender и Viewer.
- Через дополнительные модули: HTTP Proxy, TLS, лимиты запросов и блокировки IP, просмотр HTTP-трафика, TCP/UDP-пакетов и экспорт PCAP.

Панель рассчитана на один Docker-хост и сервисы одной команды. Полная приёмка на соревновательном Linux-стенде ещё не завершена; [проверки и ограничения](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/progress.md).

## Выбрать способ установки

| Вариант | Как работает панель | Когда выбирать |
|---|---|---|
| [Docker Compose](#docker-compose) | Два контейнера: dashboard и executor | Развёртывание из исходников через Compose |
| [Нативно с systemd](#нативно-с-systemd) | Готовый бинарник, две системные службы | Установка без сборки Go/npm на сервере |

В обоих вариантах игровые сервисы остаются в Docker. Нужны Linux, работающий Docker Engine, Docker Compose v5.5.0+, Git 2.40+ и Python 3.10+. Для нативного варианта также нужен systemd 247+. Каталог `/srv/game-services` ниже — пример общего каталога сервисов; используйте свой путь при необходимости.

## Docker Compose

На Docker-хосте скачайте проект и подготовьте каталоги:

```bash
git clone https://github.com/jemozing/ctf_admin_panel.git
cd ctf_admin_panel
sudo mkdir -p /srv/game-services /srv/ctf-workspaces

sudo python3 scripts/compose-bootstrap.py \
  --host-metrics \
  --discovery-root /srv/game-services \
  --workspace-root /srv/ctf-workspaces

sudo docker compose --env-file /srv/ctf-manager/config/compose.env build
```

Создайте первого администратора. Введите пароль длиной от 12 байт после `read` и нажмите Enter; символы пароля не отображаются:

```bash
sudo -v
read -r -s CTFM_INITIAL_PASSWORD
printf '%s\n' "$CTFM_INITIAL_PASSWORD" | \
  sudo docker compose --env-file /srv/ctf-manager/config/compose.env \
  run --rm --no-deps -T dashboard init-admin \
  --state /var/lib/ctf-manager --username admin
unset CTFM_INITIAL_PASSWORD

sudo docker compose --env-file /srv/ctf-manager/config/compose.env up -d
```

Откройте **http://127.0.0.1:8765/** на сервере. Вход: `admin` и заданный пароль. Для доступа с другого компьютера используйте [SSH-туннель](#доступ-со-своего-компьютера).

Bootstrap подключает только указанные каталоги. Установка панели не запускает и не пересоздаёт игровые сервисы. [Подробная установка и обновление через Compose](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/container-deployment.md).

## Нативно с systemd

Готовый архив содержит веб-интерфейс внутри бинарника, установщик, systemd-службы и примеры конфигурации. Go и Node.js на сервере не нужны.

1. Откройте [Actions → Native release](https://github.com/jemozing/ctf_admin_panel/actions/workflows/native-release.yml), нажмите **Run workflow** и дождитесь завершения.
2. Скачайте artifact **native-linux-packages** и распакуйте zip. Внутри — два Linux-архива и файл `SHA256SUMS`. Опубликованные версионные архивы также будут доступны в [Releases](https://github.com/jemozing/ctf_admin_panel/releases).
3. Перенесите файлы на сервер. Для обычного x86-64 Linux выберите `amd64`; для ARM64 — `arm64`.

В каталоге со скачанными файлами:

```bash
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf ctf-manager_*_linux_amd64.tar.gz
cd ctf-manager_*_linux_amd64

python3 install.py --dry-run
sudo python3 install.py \
  --discovery-root /srv/game-services \
  --workspace-root /srv/ctf-workspaces
```

Для ARM64 замените `amd64` на `arm64` в имени архива и каталога. Установщик проверяет пакет и зависимости, создаёт служебного пользователя и не запускает службы автоматически.

Создайте администратора и включите панель:

```bash
sudo -v
read -r -s CTFM_INITIAL_PASSWORD
printf '%s\n' "$CTFM_INITIAL_PASSWORD" | \
  sudo runuser -u ctfm-web -g ctfm-ipc -- \
  /usr/local/bin/ctf-manager init-admin \
  --state /var/lib/ctf-manager/dashboard --username admin
unset CTFM_INITIAL_PASSWORD

sudo systemctl enable --now ctfm-executor ctfm-dashboard
sudo systemctl status ctfm-executor ctfm-dashboard --no-pager
```

Панель откроется на **http://127.0.0.1:8765/**. Логи:

```bash
sudo journalctl -u ctfm-executor -u ctfm-dashboard -f
```

Dashboard работает от непривилегированного пользователя, executor — с правами управления Docker и разрешёнными каталогами. Конфигурация находится в `/etc/ctf-manager`, состояние — в `/var/lib/ctf-manager`.

Это отдельная установка: переход с работающей Compose-панели требует переноса состояния. [Нативная установка, обновление и дополнительные модули](docs/native-install.md).

## Доступ со своего компьютера

Оба варианта по умолчанию слушают loopback сервера. Выполните на своём компьютере:

```bash
ssh -N -L 8765:127.0.0.1:8765 user@SERVER
```

Откройте **http://127.0.0.1:8765/**. Для постоянного сетевого доступа настройте HTTPS и разрешённые Host по [инструкции](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/dashboard.md).

## Добавить первый сервис

1. Разместите проект внутри разрешённого каталога, например `/srv/game-services/vuln-service`, и запустите его через Docker Compose на этом хосте.
2. Войдите как Admin → **Добавить сервис** → **Выбрать папку**. Можно ввести полный путь вручную, без кавычек: `/srv/game-services/vuln-service`.
3. Проверьте компоненты, обновляемые файлы и хранилища. Значимые игровые данные должны храниться отдельно от обновляемого кода.
4. Подтвердите регистрацию и дождитесь создания исходного снимка и рабочей копии.
5. При необходимости подключите Git URL. Дальше: **Получить из Git → Build → Deploy**; для возврата — **Rollback**.

Текущая регистрация импортирует уже созданные Compose-контейнеры. Она не выполняет первый запуск нового проекта из одной папки или Git URL. [Подробности регистрации](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/registration.md).

## Собрать самостоятельно

В checkout проекта на машине сборки нужны Go 1.26+, Node.js 22.12+, npm и Python 3.10+:

```bash
make build                       # бинарник панели для текущей системы
make proxy-build capture-build   # дополнительные модули
make native-release VERSION=v0.1.0
```

Последняя команда создаёт архивы Linux amd64/arm64 и контрольные суммы в `dist/`. Сборка через Actions даёт тот же формат без установки компиляторов на игровой сервер. [Сборка, artifacts и выпуск по тегу](docs/native-release.md).

## Документация

- [Нативная установка и обслуживание](docs/native-install.md), [сборка и выпуск архивов](docs/native-release.md).
- [Docker Compose](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/container-deployment.md), [регистрация сервисов](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/registration.md), [Git-источники](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/git-sources.md).
- [HTTP Proxy, TLS и WAF](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/http-proxy-install.md), [захват пакетов](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/packet-capture-deployment.md), [TCP-потоки и gRPC](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/traffic-analysis.md).
- [Резервное копирование](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/backup.md), [хранилище и квоты](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/storage.md).
- [ТЗ](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/technical-specification.md), [матрица проверок](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/progress.md), [разработка и тесты](https://github.com/jemozing/ctf_admin_panel/blob/main/CONTRIBUTING.md).
