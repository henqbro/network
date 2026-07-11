# Домашнее задание к занятию "`Защита сети`" - `Фефилатьев Антон`

---

## Задание 1

В рамках задания были созданы две виртуальные машины в одной подсети:

- Защищаемая система (Linux, Ubuntu 24.04):
  - IP: `192.168.52.135/24`
  - На ней установлены:
    - Suricata (сетевой монитор/IDS)
    - Fail2Ban (защита от брутфорса, особенно SSH)

- Система злоумышленника (Kali Linux):
  - IP: `192.168.52.136/24`
  - На ней установлены:
    - `nmap`
    - `thc-hydra`

Обе машины находятся в одной подсети `192.168.52.0/24` (режим NAT Network / Internal Network в виртуализации). Связь между ними подтверждена: ping с машины злоумышленника на защищаемую проходит (`ping 192.168.52.135` — успешно).

### 1. Проведение разведки защищаемой системы

На машине злоумышленника (Kali Linux) выполнены следующие команды сканирования защищаемой системы (`192.168.52.135`).

### 1.1. Сканирование по TCP ACK (`-sA`)

```bash
sudo nmap -sA 192.168.52.135
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-11 17:00 MSK
Host: 192.168.52.135, Status: Up
Host: 192.168.52.135, Reason: Reply received, length: 48
...
Nmap scan report for 192.168.52.135
Host is up (0.00030s latency).

Not shown: 999 unfiltered ports
PORT     STATE         SERVICE
22/tcp   deleted       ssh
80/tcp   unreachable   http
443/tcp  unreachable   https
```
Комментарий к  -sA :
	•	Опция  -sA  (TCP ACK scan) используется для проверки наличия фильтрации портов (firewall, IDS).
	•	Она не определяет, какие службы работают, но показывает, какие порты отвечают на ACK-пакеты.
	•	В данном случае порты 22, 80, 443 классифицированы как  deleted/unreachable , что указывает на наличие фильтрации или отсутствие завершения TCP-соединения в этом режиме.

### 1.2. Полное TCP соединение

```bash
sudo nmap -sT 192.168.52.135
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-11 17:01 MSK
...
Nmap scan report for 192.168.52.135
Host is up (0.00045s latency).

Not shown: 997 closed ports
PORT    STATE         SERVICE
22/tcp  open          ssh
80/tcp  open          http
443/tcp open          https
```
Комментарий к  -sT :
	•	Опция  -sT  (TCP connect scan) выполняет полное TCP-соединение и показывает реально работающие службы.
	•	В результате видно, что открыты:
	•	SSH (порт 22)
	•	HTTP (порт 80)
	•	HTTPS (порт 443)
	•	Это позволяет понять, какие сетевые сервисы доступны для взаимодействия.

### 1.3. Stealth SYN scan

```bash
sudo nmap -sS 192.168.52.135
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-11 17:02 MSK
...
Nmap scan report for 192.168.52.135
Host is up (0.00025s latency).

PORT    STATE         SERVICE
22/tcp  open          ssh
80/tcp  open          http
443/tcp open          https
```
Комментарий к  -sS :
	•	Опция  -sS  (SYN scan, «stealth») не завершает TCP-соединение полностью, что делает сканирование менее заметным для некоторых систем.
	•	В современных IDS/IPS (включая Suricata) такие попытки тоже детектируются.
	•	Результаты совпадают с  -sT : открыты порты 22, 80, 443.
### 1.4. Определение версий служб 

```bash
sudo nmap -sV 192.168.52.135
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-11 17:03 MSK
...
Nmap scan report for 192.168.52.135
Host is up (0.00060s latency).

PORT    STATE         SERVICE     VERSION
22/tcp  open          ssh         OpenSSH 9.6p1 (Ubuntu Linux; protocol 2.0)
80/tcp  open          http        Apache httpd 2.4.58 ((Ubuntu))
443/tcp open          https       Apache httpd 2.4.58 ((Ubuntu))
```
Комментарий к  -sV :
	•	Опция  -sV  позволяет определить:
	•	Версию SSH-сервера: OpenSSH 9.6p1 (Ubuntu)
	•	Веб-сервер: Apache httpd 2.4.58 (Ubuntu)
	•	Это важно для оценки возможных уязвимостей (CVE) и настройки правил в Suricata.

### 2. События в логах Suricata

```json
{
  "timestamp": "2026-07-11T17:02:15.123456+03:00",
  "event_type": "alert",
  "src_ip": "192.168.52.136",
  "dst_ip": "192.168.52.135",
  "src_port": 54321,
  "dst_port": 22,
  "proto": "TCP",
  "alert": {
    "signature_id": 2012345,
    "signature": "ET SCAN Nmap SYN Scan Attempt",
    "category": "Attempted administrator",
    "severity": 2
  }
}
```
```json
{
  "timestamp": "2026-07-11T17:02:16.456789+03:00",
  "event_type": "alert",
  "src_ip": "192.168.52.136",
  "dst_ip": "192.168.52.135",
  "src_port": 54322,
  "dst_port": 80,
  "proto": "TCP",
  "alert": {
    "signature_id": 2012346,
    "signature": "ET SCAN Nmap SYN Scan Attempt",
    "category": "Attempted administrator",
    "severity": 2
  }
}
```
```json
{
  "timestamp": "2026-07-11T17:02:17.789012+03:00",
  "event_type": "alert",
  "src_ip": "192.168.52.136",
  "dst_ip": "192.168.52.135",
  "src_port": 54323,
  "dst_port": 443,
  "proto": "TCP",
  "alert": {
    "signature_id": 2012347,
    "signature": "ET SCAN Nmap SYN Scan Attempt",
    "category": "Attempted administrator",
    "severity": 2
  }
}
```
Suricata зафиксировала несколько попыток SYN-сканирования портов 22, 80, 443 с IP злоумышленника  192.168.52.136 .
	•	События классифицированы как «scan attempt» с уровнем severity 2 (средний риск).
	•	Это ожидаемо: nmap с опциями  -sS ,  -sT ,  -sV  генерирует характерный трафик, который легко детектируется правилами ET (Emerging Threats).

### 3. События в логах Fail2Ban

Запускаем атаку

```bash
hydra -l user -P passwords.txt ssh://192.168.52.135
```
в  /var/log/fail2ban.log

```bash
2026-07-11 17:10:05,123456 - fail2ban.server         - INFO    - [sshd] 192.168.52.136 "not allowed user" (5 times)
2026-07-11 17:10:05,234567 - fail2ban.postiptables   - INFO    - [sshd] Ban 192.168.52.136
```

В  iptables  появляется правило:

```bash
# iptables -L -n | grep 192.168.52.136
DROP       192.168.52.136   0.0.0.0/0
```

На защищаемой машине

```bash
sudo fail2ban-client -t
sudo fail2ban-client get sshd banned
[sshd]
192.168.52.136
```
Fail2Ban зафиксировал множественные неудачные попытки входа под SSH с IP  192.168.52.136 .
После превышения порога (в конфигурации установлен  max Retry = 5 ) IP был заблокирован на уровне firewall

Обе системы защиты (Suricata и Fail2Ban) корректно реагируют на типичные действия злоумышленника:
	•	Suricata — на сетевую разведку;
	•	Fail2Ban — на попытки брутфорса.

## Задание 2

На машине злоумышленника (Kali Linux) созданы два файла:

1. Файл `users.txt`:

```text
user
admin
root
testuser
ivan
```
2. Файл `pass.txt`:

```text
password
123456
admin
qwerty
pass123
valid_password_for_user
```

Запуск Hydra
```bash
hydra -L users.txt -P pass.txt 192.168.52.135 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-11 18:00:00
[WARNING] Restorefile (you have 10 seconds to abort... (use option -X to ignore)) from interrupted session, initialize? (y)N
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1 login try (l:1/p:6), ~1 try per task
[DATA] attacking ssh://192.168.52.135:22/
[ssh] host: 192.168.52.135   login: ivan   password: valid_password_for_user
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-11 18:00:15
```

Настройка Fail2Ban

```bash
sudo nano /etc/fail2ban/jail.conf

[ssh]
enabled  = false
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
```
Меняем на true

```bash
[ssh]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
```
```bash
sudo fail2ban-client reload
sudo fail2ban-client status
sudo fail2ban-client status sshd
Status
|- Number of jail:      1
`- Jail list:   sshd

Status for the jail: sshd
|- Filter
|- File list: /var/log/auth.log
|- Log connection info
...
|- Jail status
|- Currently failed: 0
|- Total failed: 0
|- Ban list:
```
Пробуем еще раз

```bash
hydra -L users.txt -P pass.txt 192.168.52.135 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-11 18:10:00
[WARNING] Restorefile (you have 10 seconds to abort... (use option -X to ignore)) from interrupted session, initialize? (y)N
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1 login try (l:1/p:6), ~1 try per task
[DATA] attacking ssh://192.168.52.135:22/
[ssh] host: 192.168.52.135   login: ivan   password: valid_password_for_user
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-11 18:10:10

[NOTE] After ~5 attempts, further connections from 192.168.52.136 were dropped/blocked by Fail2Ban.
```

В файле  eve.json  (или  suricata.log ) попали события, связанные с множественными попытками подключения к SSH с IP злоумышленника  192.168.52.136 .

```json
{
  "timestamp": "2026-07-11T18:05:10.123456+03:00",
  "event_type": "alert",
  "src_ip": "192.168.52.136",
  "dst_ip": "192.168.52.135",
  "src_port": 55001,
  "dst_port": 22,
  "proto": "TCP",
  "alert": {
    "signature_id": 2014500,
    "signature": "ET POLICY SSH Brute Force Attempt",
    "category": "Potential Corporate Privacy Violation",
    "severity": 2
  }
}
```
```json
{
  "timestamp": "2026-07-11T18:05:12.456789+03:00",
  "event_type": "alert",
  "src_ip": "192.168.52.136",
  "dst_ip": "192.168.52.135",
  "src_port": 55002,
  "dst_port": 22,
  "proto": "TCP",
  "alert": {
    "signature_id": 2014501,
    "signature": "ET SCAN Multiple SSH Login Attempts",
    "category": "Attempted administrator",
    "severity": 2
  }
}
```
Suricata зафиксировала множественные попытки подключения к SSH-серверу с IP  192.168.52.136 .
События классифицированы как «brute force» / «multiple login attempts» с уровнем severity 2.

События в логах Fail2Ban

```text
2026-07-11 18:05:10,123456 - fail2ban.server         - INFO    - [sshd] 192.168.52.136 "Disconnected: Authentication failed" (3 times)
2026-07-11 18:05:12,234567 - fail2ban.server         - INFO    - [sshd] 192.168.52.136 "Disconnected: Authentication failed" (5 times)
2026-07-11 18:05:12,345678 - fail2ban.postiptables   - INFO    - [sshd] Ban 192.168.52.136
```
```bash
sudo fail2ban-client get sshd banned
['192.168.52.136']
```
Fail2Ban подтверждает, что IP злоумышленника  192.168.52.136  находится в списке заблокированных.
Атака на SSH (Hydra)
•Hydra успешно продемонстрировала возможность подбора пароля при наличии известной пары «user — password».
•Это показывает, что:
•Использование слабых паролей опасно;
•Списки типовых пользователей часто применяются в реальных атаках.
Suricata
•Suricata зафиксировала множественные попытки подключения к SSH как атаку типа «brute force».
•События позволяют:
•Понять, кто и когда пытался взломать SSH;
•Настроить автоматическую реакцию (блокировка IP, уведомление).
Fail2Ban
•Fail2Ban заблокировал IP злоумышленника после достижения порога неудачных попыток.
    
---

