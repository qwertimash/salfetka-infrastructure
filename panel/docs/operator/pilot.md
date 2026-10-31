# Постоянная установка закрытого пилота

Обновление27октября: действующая public admin/delivery выдача направлена прямо
на DE, доверенный TLS продлевает DE certbot; FI edge сохранён для отката.
Ниже описана базовая установка, а не команда повторного переноса.
[Текущее размещение, ограничения и RU-миграция](../../../docs/infrastructure-repair-results-20261027.md).

Это отдельная установка собственной панели. Production Remnawave, бот, их БД,
ключи, порты и конфиги в неё не переносятся. Назначение — выдача доступа первым
тестерам с последующим развитием; после тестирования её не нужно удалять.
Установка на действующую Германию требует согласования конкретной области записи.

## Размещение и ресурсы

Предлагаемая область: `/opt/salfetka-pilot`, отдельный непривилегированный владелец,
Compose project `salfetka-pilot`; база только во внутренней Docker-сети.
Админка — `127.0.0.1:18463`, доступ через SSH; публикация только персональных
подписок на отдельном домене и свободном порту, например `18483`.
Административный API и API узлов на delivery listener возвращают 404 даже с
действующей admin cookie. Ключи подписи узлов и CA туда не монтируются.
Delivery имеет runtime-доступ к БД и master key: это уменьшение поверхности
атаки, а не полная изоляция от последствий компрометации публичного процесса.

Суммарные верхние CPU-квоты PostgreSQL/admin/delivery/worker — 1 CPU; лимиты
памяти — 992 MiB. Setup дополнительно ограничен 0,25 CPU/128 MiB, запускается
однократно. Admin получает 384 MiB и Go soft limit 320 MiB: четыре
параллельных Argon2-проверки используют до 256 MiB, плюс heap/процесс. Эти числа не включают Docker/host overhead и будущие VPN-ядра.
Логи ограничены 15 MiB на сервис; размер БД/backup не ограничен этим параметром.
Перед запуском проверить текущую нагрузку, свободные порты/диск, Docker/Compose,
CPU-квоту провайдера. Наличие 4 vCPU само по себе не гарантирует длительный бюджет.
Не менять firewall, DNS, reverse proxy, production containers или системный VPN
автоматически. Для публичного endpoint отдельно нужны DNS и доверенный TLS.

## Сборка вне сервера

В основной рабочей папке после проверок:

```sh
panel/scripts/build.sh
sh panel/scripts/package-pilot.sh amd64 panel/artifacts/pilot-linux-amd64
```

Получается allowlisted build context с Linux-бинарниками, web, лицензиями,
инструкцией и SHA256 каждого файла. Private каталоги и БД туда не входят.
Проверить хеши перед сборкой образа. `git_head` сопровождается признаком WIP:
он не выдаёт незафиксированные изменения за содержимое commit.

На отдельной машине сборки с Docker, из каталога комплекта:

```sh
docker build --platform linux/amd64 -f deploy/pilot/Dockerfile -t salfetka-panel:pilot-20261025-amd64 .
docker save -o panel-image.tar salfetka-panel:pilot-20261025-amd64
```

В Dockerfile только pinned FROM/COPY, без компиляции. Образ, его digest и SHA256
архива проверяются при переносе. `docker load` на целевом сервере выполняется
только после разрешения. ARM64 комплект собирается отдельно; запуск ARM64 не
является runtime-приёмкой AMD64.

## Создание новой установки

Под отдельным Unix-пользователем, из распакованного Linux-комплекта:

```sh
python3 scripts/prepare-pilot.py --dir /opt/salfetka-pilot/install \
  --origin https://SUBSCRIPTION_DOMAIN:18483 --bind 0.0.0.0 \
  --image salfetka-panel:pilot-20261025-amd64 \
  --cert /private/fullchain.pem --key /private/privkey.pem
cd /opt/salfetka-pilot/install
docker compose --env-file compose.env -f compose.json config --quiet
docker compose --env-file compose.env -f compose.json up -d postgres
docker compose --env-file compose.env -f compose.json run --rm setup migrate
docker compose --env-file compose.env -f compose.json run --rm setup provision-runtime --password-file /run/panel/runtime-password
docker compose --env-file compose.env -f compose.json run --rm setup bootstrap --token-file /run/panel/bootstrap.json
docker compose --env-file compose.env -f compose.json up -d admin delivery worker
```

`SUBSCRIPTION_DOMAIN` — обязательная замена, не созданная DNS-запись. Каталог
должен быть новым; повторный prepare его не перезаписывает. Права 0700/0600.
Скрипт проверяет пару ключ/сертификат, имя и срок более суток; проверка доверенной
цепочки и внешнего DNS остаётся отдельной. `--lab` допускает self-signed только
для localhost/loopback. Секреты и `compose config` без `--quiet` не печатать.
Bootstrap-токен одноразовый, 30 минут; вводить через защищённую форму владельца.

SSH tunnel: `ssh -N -L 18463:127.0.0.1:18463 APPROVED_HOST`, затем
`https://localhost:18463`. Админский сертификат проверяется по сохранённому
сертификату; исключение TLS для публичной подписки недопустимо. `/healthz`
подтверждает процесс, `/readyz` — готовность БД/schema. В deployed delivery
`delivery-tls-20261027` публичная пара перечитывается без restart, с сохранением
предыдущей валидной пары при ошибке. Admin public edge использует nginx reload;
внутренний pinned TLS этим механизмом не меняется.
[Установленные renewal hooks](../../../ops/tls-maintenance/README.md).

Внутренний TLS admin нельзя менять отдельно от доверия уже зарегистрированных
нод. Агент хранит SHA256 доверенного PEM не только в `server-ca.crt`, но и в
`identity/state.json`; простая подмена файла CA приведёт к отказу при restart.
При плановой ротации заранее подготовить согласованную миграцию trust/pin с
private backup и остановкой только соответствующих pilot agents. Ключи,
enrollment и node ID сохранять, повторное enrollment не использовать как обход.
Приёмка после ротации: свежий heartbeat **и VPN receipt каждой ноды**, затем
проверка endpoint. Успешный вход в браузер и `/readyz` этого не подтверждают.
[Разбор и восстановление 26 октября](../pilot-trust-repair-20261026.md).

## Выдача доступа

Создать пользователя → выдать право с датой окончания → зарегистрировать
устройство → принять источник или подключить свой узел → собрать версию →
опубликовать → создать персональную ссылку. Обновление опубликованного конфига
сохраняет ссылку. Замена ссылки закрывает предыдущую; отзыв ссылки закрывает
скачивание. Это не отзыв уже скачанного внешнего VPN-ключа.

Для настоящих тестеров нужны проверенные узлы и регистрация из приложения.
Локальная приёмка использует синтетическую Ed25519-регистрацию и синтетический
источник: она не заменяет реальный HTTPS-трафик через VPN, Jitsi, физический
iPhone или проверку белых списков. Managed node нужно отдельно подключить к
приватному admin endpoint с mTLS; наружу agent API через delivery не открывать.
Первые подписки выдавать после проверки обычного VPN и обхода, срока, отзыва
активной сессии и переноса A без обрыва B. Массовую выдачу на 100 пользователей
этот ресурсный профиль не подтверждает.

## Backup, восстановление и откат

До обновления сохранить private secrets (master key, CA, signer и DSN), образ
по digest и PostgreSQL custom dump в закрытый каталог вне контейнеров. Пример
из каталога установки:

```sh
umask 077
docker compose --env-file compose.env -f compose.json exec -T postgres \
  pg_dump -U panel_migrator -d panel -Fc > /PRIVATE_BACKUP/panel.dump
```

Сохранение дампа не доказывает восстановление. Создать отдельную неактивную БД,
восстановить через `pg_restore --exit-on-error`, сравнить число пользователей,
подписок, их active/token state; проверить runtime role grants. Не подключать
восстановленную копию к реальным агентам/выдаче: перед активацией нужен fencing
старой authority и исключение возврата отозванных прав. Полный B11 ещё открыт.

Откат нового пилота: остановить только `salfetka-pilot` admin/delivery/worker,
сохранить БД/secrets/логи, вернуть прежний совместимый образ. При несовместимой
миграции сначала отдельная проверка restore, не запускать старый образ вслепую.
Не использовать `down --volumes` для действующей установки и не чистить общие
Docker resources. Удаление volume допустимо только для явно одноразовой локальной
приёмки с синтетическими данными.
