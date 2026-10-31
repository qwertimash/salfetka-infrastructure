# Отдельная служба на Linux: установка P3

Панель не получает SSH/root. Создание карточки не устанавливает агент.
Один агент управляет одним подключением (VLESS TLS, Hy2 или Jitsi).
Несколько подключений на одной физической машине устанавливаются как **отдельные
instances**, с разными identity, state, service users и портами. Это текущая
изоляция движков. Карточка физического сервера объединяет подключения в панели;
она не заменяет identity служб. Прежние узлы доступны отдельно без пересоздания.

Пакеты `package-vpn-node.sh amd64|arm64` / `package-bypass-node.sh` включают
`install-node.py`. Установщик принимает только локальный пакет с проверкой
контрольных сумм executable/unit и архитектуры ELF. Доверие к происхождению
самого пакета — отдельная проверка release; SHA256SUMS не цифровая подпись.

1. Создать узел в панели, скачать его enrollment. Получить **публичные** TLS CA
   панели и signer public key по доверенному каналу. Приватные ключи панели
   не передавать. Выделить отдельный порт>=1024 и сертификат VPN с нужным именем.
2. Создать приватный JSON spec по примеру ниже. UUID установки создать один раз,
   сохранить и затем ввести в расширенных параметрах VPN карточки узла.
3. На целевом Linux: `python3 install-node.py plan --package . --spec ./node.json`.
   Plan проверяет inputs/checksums/свободный TCP или UDP port, ничего не записывает.
4. `sudo python3 install-node.py install --package . --spec ./node.json`:
   проверка отсутствия чужого unit/user/каталога, копирование, enrollment и
   initialize. Служба ещё НЕ запущена. Enrollment-копия удаляется после успеха;
   исходный файл оператор удаляет самостоятельно. При сбое данные сохраняются
   для разбора, повтор не перезаписывает установку и не меняет identity.
5. Узел зарегистрирован: сохранить VPN endpoint в панели с тем же installation
   UUID и endpoint. Затем `sudo python3 install-node.py activate --instance de-vless`.
   Проверить отдельно heartbeat и подтверждение движка, затем настоящий трафик.
6. Откат/снятие службы: `sudo python3 install-node.py disable --instance de-vless`.
   Проверяется owner marker и неизменность unit; disable/stop только этой службы.
   Identity, state, конфиги, user сохраняются. Автоматической очистки каталогов,
   firewall или удаления history нет. Изменённый чужими руками unit не трогается.

```json
{
  "instance": "de-vless",
  "node_id": "00000000-0000-4000-8000-000000000001",
  "installation_id": "00000000-0000-4000-8000-000000000002",
  "panel_url": "https://node-api.example.com:8443",
  "backend": "vless",
  "ca_file": "/root/setup/server-ca.crt",
  "signer_file": "/root/setup/signer.pub",
  "enrollment_file": "/root/setup/enrollment.json",
  "listen_ip": "0.0.0.0",
  "port": 19443,
  "certificate_file": "/root/setup/vpn.crt",
  "key_file": "/root/setup/vpn.key"
}
```

Для Hy2 backend=`hysteria2`, проверяется UDP. Для Jitsi backend=`olcrtc`, вместо
TLS/listener полей — `endpoint_file` с исходным typed endpoint JSON панели.
Обычный `package-bypass-node.sh` собирает закреплённый managed upstream без
account-session overlay. Для `account_session`/`personal_rooms` необходим отдельно
проверенный пакет с соответствующими capabilities; простой пакет не подходит.
Не отключайте одну сессию ради обхода ошибки capability. Локальная проверка
account overlay не является публикацией нового release форка.
Каталоги, binaries и обычные конфиги принадлежат root; TLS private key и временный
enrollment — service UID с0600, как требуют строгие загрузчики ядра.
Секреты и endpoint не выводятся в receipt. Известные unit hardening/CPU-memory
ограничения пакета сохраняются; firewall/DNS/маршруты установщик не меняет.
Новый port может занять другой процесс после preflight: bind движка тогда
завершится ошибкой; нельзя освобождать его остановкой чужой службы.

Локальные unit tests проверяют план, checksum, архитектуру, symlinks, конфликты,
изоляцию, повтор и permissions. systemd/enrollment/реальная VPN-приёмка Linux
должны пройти на выделенной машине отдельно перед rollout. На production этот
установщик не запускался.
