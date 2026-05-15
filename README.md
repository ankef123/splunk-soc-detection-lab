# Splunk SOC Detection Lab

Практическая SOC-лаборатория, созданная для демонстрации навыков: **сбор логов, анализ событий в SIEM, разработка детектов на SPL, расследование Windows-событий, работа с сетевой телеметрией и валидация use case’ов мониторинга**.

Этот проект моделирует небольшую enterprise-like инфраструктуру с **сегментированной сетью**, **Splunk в роли SIEM**, **Windows endpoint и authentication telemetry**, а также **Suricata IPS**, установленной inline для сетевого контроля и наблюдения.

---

## Структура репозитория

```text
.
├── README.md 
├── task.md #сгенерированное + отредактированное задание "лабы"
├── topology.md #информация об архитектурных решениях, IP-адресации и тд
├── attacks/ #подготовка + сама атака; источники логов; SPL; настройки алерта; его срабатывание; мои мысли и действия по расследованию; MITRE ATT&CK mapping
├── suricata_rules/ #Правила Suricata, используемые в лабе 
└── screenshots/ #скриншоты
```

---

## Зачем я сделал эту лабораторию

Эта лаборатория была создана, чтобы выйти за рамки теории и получить практический опыт, приближенный к реальным задачам SOC:

- собирать телеметрию из нескольких источников;
- анализировать Windows- и network-события безопасности;
- строить и проверять детекты в Splunk;
- коррелировать сетевую и хостовую активность;
- оформлять use case’ы и результаты в структурированном техническом виде.

Главная цель этого репозитория — собрать **небольшую, но логичную среду мониторинга**, где инфраструктура, логи, детекты и симуляции активности связаны в единый workflow.

---

## Навыки, продемонстрированные в лабораторной работе

Эта лаборатория показывает следующие практические навыки:

- **базовая работа с SIEM на базе Splunk**
- **анализ Windows Event Logs**
- **endpoint visibility через Sysmon**
- **анализ PowerShell logging и suspicious execution**
- **мониторинг аутентификации через Windows Server / AD-события**
- **сетевой мониторинг и базовое предотвращение через Suricata IPS**
- **основы detection engineering**
- **построение use case’ов на SPL**
- **MITRE ATT&CK mapping**
- **базовый incident investigation workflow**
- **Настройка и развёртывание: Splunk SIEM и её компонентов / Suricata**
- **Администрирование ПО, имитирующего сервисы компании**

---

## Цель лаборатории

Лаборатория построена вокруг практической задачи SOC-аналитика:

> собрать телеметрию, воспроизвести подозрительную активность, проверить срабатывание детектов и оформить результаты в виде портфолио-проекта.

Основные задачи:
- развернуть сегментированную SOC-лабораторию;
- централизовать логи в Splunk;
- собирать host, authentication и network telemetry;
- реализовать несколько detection use case’ов;
- валидировать их на контролируемых сценариях;

---

## Архитектура лаборатории

![screenshots/topology.png](screenshots/topology.png)
[Подобная информация по топологии](/topology.md)

---

## Моделируемые сценарии атак и подозрительной активности

В лаборатории моделируются не случайные действия, а набор **сценариев**, которые позволяют проверить сбор телеметрии, качество детектов и базовую корреляцию между host-, authentication- и network-источниками.
[Почему именно эти атаки?](/attacks-list.md)

### 1. Brute force / password spraying с последующим успешным входом
[Bruteforce сценарий](attacks/01_bruteforce_success.md)

### 2. Encoded PowerShell execution
[Encoded PowerShell execution](attacks/02_encoded_powershell.md)

### 3. Suspicious PowerShell download activity
[Suspicious PowerShell download](attacks/03_powershell_download.md)

### 4. Office → PowerShell / cmd execution chain
[Office → PowerShell](attacks/04_office_powershell_cmd_chain.md)

### 5. Execution from Temp / AppData / user-writable directories
[Execution from user-writable directories](attacks/05_execution_from_suspicious_dirs.md)

### 6. Suspicious traffic toward DMZ services
[Suspicious traffic toward DMZ](attacks/06-07_suspicious_dmz_traffic_-IPS_blocking.md)

### 7. Inline IPS alert / blocking demonstration
[Inline IPS alert / blocking demonstration](attacks/06-07_suspicious_dmz_traffic_-IPS_blocking.md)

### 8. Suspicious account management activity
[account management activity](attacks/08_suspicious_account_management.md)

---

## Основные источники данных

Проект ориентирован на сбор и анализ данных из нескольких источников.

### Windows Client
- Windows Security logs
- Sysmon
- PowerShell Operational / Script Block logs
- process execution telemetry

### Windows Server
- Security logs
- authentication events
- account management events
- domain / infrastructure-related activity

### Suricata IPS
- alert events
- flow metadata
- protocol-related records (HTTP / DNS / TLS при наличии)

### Linux / DMZ host
- web server logs
- SSH / system logs
- серверная сетевая активность

---

## На чем сфокусирована лаборатория

Эта лаборатория строится не вокруг “набора инструментов”, а вокруг **практических SOC-детектов**. То есть, фокус строится не только на установке ПО, а на полной цепочке:
**инфраструктура -> телеметрия -> детектирование -> валидация -> документация**

Примеры направлений, которые покрывает проект:

- **Brute force с последующим успешным входом**
- **Encoded PowerShell execution**
- **Подозрительная загрузка через PowerShell**
- **Нетривиальные process execution chains**
- **Корреляция endpoint- и network-событий**
- **Подозрительная активность в сторону внутренних или DMZ-сервисов**

Фокус проекта — не просто написать поисковый запрос, а понять:
- откуда берется телеметрия;
- какие логи нужны для детекта;
- почему этот сценарий важен;
- как его валидировать;
- какие возможны ложные срабатывания;
- какие ограничения есть у правила;
- как расследовать suspicious activity по нескольким источникам;
- как строить детекты вокруг наблюдаемых attacker techniques;
- технически грамотно документировать результаты.
