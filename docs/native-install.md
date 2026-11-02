# Нативная установка с systemd

Готовый Linux-архив содержит бинарник `ctf-manager` со встроенным веб-интерфейсом, установщик и две systemd-службы. Go, Node.js и checkout исходников на сервере не требуются. Игровые сервисы продолжают работать в Docker.

## Что требуется

- Linux с systemd **247 или новее**, архитектура `amd64` (`uname -m` показывает `x86_64`) или `arm64` (`aarch64`).
- Docker Engine с локальным Unix socket и Docker Compose **v5.5.0 или новее**.
- Python 3.10+, Git, системные корневые CA-сертификаты, `sudo` и `runuser`.
- Отдельные каталоги игровых проектов и подготовки исходников. Стандартные пути — `/srv/game-services` и `/srv/ctf-workspaces`.

Установщик проверяет зависимости, целостность пакета и архитектуру. Системные пакеты автоматически не устанавливаются. Нативная поставка не является автоматической миграцией работающей Compose-панели: её конфигурация, реестр и пользователи не копируются. Старую панель нужно отдельно остановить и сохранить её данные; игровые контейнеры останавливать не требуется. Два executor не должны одновременно управлять одними сервисами.

## Скачать пакет

В GitHub откройте **Actions → Native release → Run workflow**. Пустая версия создаёт сборку `dev-<commit>`. После успешного запуска скачайте артефакт **native-linux-packages**. Он содержит архивы двух архитектур и общий `SHA256SUMS`.

Для опубликованной версии те же архивы доступны в [GitHub Releases](https://github.com/jemozing/ctf_admin_panel/releases). Версионный релиз появляется после отдельного запуска tag-процедуры; наличие workflow само по себе его не создаёт. [Порядок сборки и выпуска](native-release.md).

Распакуйте скачанный zip, перейдите в каталог с файлами и проверьте архивы:

```sh
sha256sum --ignore-missing -c SHA256SUMS
```

Команда проверяет скачанные архивы; отсутствие архива другой архитектуры не считается ошибкой. Выберите архив своей архитектуры. В следующих командах замените `VERSION` точной версией из имени скачанного файла:

```sh
tar -xzf ctf-manager_VERSION_linux_amd64.tar.gz
cd ctf-manager_VERSION_linux_amd64
python3 install.py --dry-run
```

Для ARM64 используйте суффикс `linux_arm64`. Скачивайте архив и контрольные суммы из одного доверенного запуска workflow или релиза. Установщик дополнительно проверяет внутренние суммы файлов перед копированием.

`--dry-run` проверяет пакет и выводит план без изменений хоста. Наличие зависимостей, systemd и подходящего Docker daemon проверяется при настоящей установке.

## Установить

Стандартные корни создаются, если ещё отсутствуют. Для других путей предварительно создайте отдельные каталоги и передайте полный список флагами `--discovery-root` и `--workspace-root`; существующие игровые файлы и их права установщик не меняет.

```sh
sudo python3 install.py \
  --discovery-root /srv/game-services \
  --workspace-root /srv/ctf-workspaces
```

Для нескольких корней повторите соответствующий флаг. Пути должны быть абсолютными и не содержать символических ссылок; корни проектов и рабочих копий не должны пересекаться. Если `docker` находится вне обычного `PATH`, укажите `--docker-binary /absolute/path/to/docker`. Локальный socket меняется через `--docker-socket /absolute/path/to/docker.sock`.

| Путь / служба | Назначение |
|---|---|
| `/usr/local/bin/ctf-manager` | Панель, executor и административные команды |
| `/etc/ctf-manager/executor.json` | Приватная конфигурация executor |
| `/var/lib/ctf-manager/dashboard` | Пользователи и сессии; владелец `ctfm-web`, права `0700` |
| `/var/lib/ctf-manager/executor` | Реестр, снимки, релизы и секреты; владелец root, права `0700` |
| `/run/ctf-manager` | Unix socket; root и группа `ctfm-ipc`, права каталога `0750` |
| `ctfm-executor.service` | Привилегированный executor с ограниченным набором capabilities |
| `ctfm-dashboard.service` | Веб-процесс пользователя `ctfm-web`, без Docker group |

UID служебного пользователя определяется при установке и записывается в конфигурацию. Установщик не запускает и не перезапускает службы; после проверки файлов выполняется только `systemctl daemon-reload`.

## Создать администратора и запустить

В bash/zsh введите пароль длиной не менее 12 байт после команды `read` и нажмите Enter. Пароль не отображается и не передаётся аргументом процесса:

```sh
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

Создание Admin выполняется от `ctfm-web`, чтобы файлы dashboard оставались доступны этому пользователю. Стандартного пароля нет; повторный `init-admin` не сбрасывает существующую учётную запись.

Откройте **http://127.0.0.1:8765/** на сервере. Для доступа со своего компьютера создайте SSH-туннель:

```sh
ssh -N -L 8765:127.0.0.1:8765 user@SERVER
```

После этого панель доступна на **http://127.0.0.1:8765/**. Если нужен другой локальный порт туннеля, добавьте соответствующий точный `Host:port` в `--allowed-hosts` dashboard через systemd override. Для другого адреса или HTTPS также настройте параметры доступа; [инструкция](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/dashboard.md).

Добавьте сервис через «Добавить сервис»: выберите его папку Docker-хоста, проверьте найденные компоненты и данные, подтвердите регистрацию. Compose-контейнеры сервиса должны уже существовать. Подробности — в [регистрации](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/registration.md).

## Обновить

Сделайте согласованный backup состояния и сохраните конфигурацию. Получите и проверьте новый архив, затем остановите только две службы панели:

```sh
sudo systemctl stop ctfm-dashboard ctfm-executor
sudo python3 install.py --upgrade
sudo systemctl start ctfm-executor ctfm-dashboard
```

Запускайте `install.py` из нового распакованного архива. Обновление сохраняет существующие конфигурацию, state, пользователей и корни. Оно требует остановленных служб и ранее установленного пакета с проверяемыми файлами; неизвестные или изменённые установленные файлы не перезаписываются молча. Для изменения корней отредактируйте доверенную конфигурацию отдельно и повторите диагностику; флаги свежей установки не являются миграцией данных.

## Диагностика и дополнительные модули

```sh
sudo journalctl -u ctfm-executor -u ctfm-dashboard -f
sudo /usr/local/bin/ctf-manager --config /etc/ctf-manager/executor.json doctor
sudo /usr/local/bin/ctf-manager --config /etc/ctf-manager/executor.json status
```

Dashboard остаётся запущен при недоступном executor и показывает ошибку связи. Перезапуск панели отзывает прежние сессии; пользователи входят снова. Для host-метрик unit executor подключает пять точных read-only procfs-файлов; широкое монтирование `/proc` и сетевой namespace контейнера для этого не нужны.

В архив также входят `ctfm-proxy`, `ctfm-traffic`, `ctfm-capture` и `ctfm-packets`. Базовый установщик создаёт службы только dashboard/executor; proxy/WAF и захват трафика требуют отдельной настройки политик, токенов, данных и процессов. Их существующие Compose-профили можно подключать независимо: [Proxy / WAF](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/http-proxy-install.md), [capture](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/packet-capture-deployment.md).

Границы подтверждённых проверок и открытая Linux/CTF-приёмка перечислены в [матрице](https://github.com/jemozing/ctf_admin_panel/blob/main/docs/progress.md).
