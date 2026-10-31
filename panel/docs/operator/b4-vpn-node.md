# B4: отдельный Xray-узел (локальная alpha)

Этот runbook относится к самостоятельной панели, не к production Telegram-боту
или Remnawave. Поддерживается VLESS RAW/TLS; остальные transports не приняты.
Демонстрация: https://localhost:18453, данные входа в приватном
`panel/private/demo-b4-20261014/Вход в панель.txt`.

## Панель

Сохранить согласованный backup PostgreSQL и private master key/CA/signer. Обновить
API/worker после явных migration001–011 и provision-runtime (как B3 runbook).
Новые immutable policies encrypted at rest, receipts, observations и публичные
endpoint metadata используют008–011. Старые001–007 не меняются. Публичная установка
и MFA gate пока открыты. Исправление boot clock recovery описано в
[результатах](../b4-clock-recovery.md). Не применять это обновление к production без разрешения.

## Новый сервер

Собрать `scripts/package-vpn-node.sh arm64` (или amd64) из проверенного source/cache.
Пакет содержит standalone binary и unit; installer автоматически не создаёт users,
не заменяет чужие службы и не меняет firewall. Полная лицензированная дистрибуция B11
ещё не принята: пакет сейчас для собственной локальной приёмки.

Выделить отдельного system user/group `salfetka-vpn-node`, без login. Сначала проверить,
что это именно новая/собственная установка: не принимать существующие чужие каталоги,
UID или unit. Binary directory `/usr/local/libexec/salfetka-vpn-node` — root0755,
config `/etc/salfetka-vpn-node` — root0755, state `/var/lib/salfetka-vpn-node` —
service0700. Установить binaries0755, unit0644. Для этой identity прежний
`panel-node run` одновременно не запускать: process lock отвергнет второй процесс.

Создать узел в панели, скачать enrollment0600 и под service user выполнить
`panel-node enroll` с B3 переменными окружения; identity directory —
`/var/lib/salfetka-vpn-node/identity`. CA HTTPS панели и public signer — root0644.
Приватные CA/signer/master key панели на узел не передавать.

В карточке узла открыть «Настроить VPN», указать адрес, порт >=1024 и TLS server name.
Скопировать идентификатор установки из раскрываемых параметров. Сохранить настройку.
В `vpn.env.example` подставить этот installation ID, node ID, origin и пути. Сохранить
как `/etc/salfetka-vpn-node/agent.env`, root0600. TLS certificate chain — root0644;
TLS key — service0600. Использовать действующий сертификат с именем endpoint.
Для отдельной лаборатории можно задать один доверенный CA в панели; проверка TLS
в клиенте никогда не отключается.

Один раз выполнить `panel-vpn-node initialize` под service user с этим окружением:
создаются owner binding и lock, пустой engine сразу закрывается. Затем проверить
unit через systemd-analyze, daemon-reload и включить только
`salfetka-vpn-node.service`. `run-managed` требует существующий binding; произвольные
config/PID/service names из панели не исполняются. Изменение локального TLS identity
или listener меняет config hash и требует отдельной миграции установки, не silent reset.

## Проверка

В панели дождаться «Применено движком» отдельно от heartbeat. Создать пользователя,
выдать право без quota, нажать «Добавить тестовое устройство», выбрать узел и скачать
Xray JSON. Это отдельная тестовая установка с browser-generated proof, не регистрация
телефона от его имени. Запустить JSON своим Xray-клиентом; локальный SOCKS —10808.
Счётчики — cumulative для текущего engine epoch; null значит «нет данных». Они не
являются биллинговым ledger и не разрешают quota_hard. UI сохраняет старые значения
при ошибке, но снимает свежесть. После приостановки/блокировки/отзыва credentials
очередной VPN poll закрывает активные TCP/UDP пользователя; другие users сохраняются.

Polling:5с между циклами, каждый запрос ограничен2с; heartbeat не задаёт частоту VPN.
Разрешение выдаётся на2мин, renewal при остатке30с; локальный50мс watchdog не зависит
от API. После crash новый process epoch требует свежую подписанную generation;
сохранённая policy не восстанавливает доступ сама. После rollback часов
старый engine закрывается; через5с supervisor пробует новый epoch с новым
разрешением панели. Пока часы ниже durable HWM, доступ закрыт. Другие ошибки
конфигурации/подписи/storage и отзыв identity остаются terminal. При потере API текущие сессии
живут только до signed deadline; после восстановления свежая policy возвращает доступ.
Отзыв node останавливает свой engine при следующем успешном ответе401; offline bound
остаётся абсолютным lease. systemd управляет только собственной cgroup.

По умолчанию Xray запрещает выход в private/loopback destinations. Переменная
`PANEL_VPN_LAB_LOOPBACK_ONLY=1` предназначена только для echo-приёмки: она разрешает
исключительно loopback egress и запрещает весь внешний. Для реального выхода в
Интернет и демонстрации18453 эта переменная отсутствует.

## Ограничения и rollback

Предел alpha —128 grants/512 candidate users на узел; превышение выдаёт явную ошибку,
не частичный config. Общая B2 outbox пока не закрывается ACK одного узла; UI показывает
подтверждение выбранного VPN-узла отдельно. Traffic ledger с финальными counters
отозванных grants и распределённый reconcile остаются отдельным незакрытым gate.
Не считать принятыми другие transports, производительность или физические iOS/Android.

До deploy откат — scoped additions относительно B3.3 snapshot. После migration
для rollback всей установки нужен согласованный backup БД/private material и прежняя
сборка, при остановленном собственном engine. Не возвращать старый HWM/epoch backup
на живой узел: это может оживить отозванный доступ. Откат Xray server patch снимает
гарантию завершения активных сессий, поэтому не допускается с активными grants.
