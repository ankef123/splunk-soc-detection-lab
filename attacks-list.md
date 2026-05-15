# Моделируемые сценарии атак и подозрительной активности

## 1. Brute force / password spraying с последующим успешным входом
**Суть сценария:** серия неуспешных попыток аутентификации с последующим успешным логоном.  
**Что проверяется:** способность выявлять подозрительную активность вокруг учетных записей и строить корреляцию между failed и successful logon events.  
**Источники:** Windows Security Logs, Windows Server.  
**Практическая ценность:** один из самых типовых сценариев для SOC.

## 2. Encoded PowerShell execution
**Суть сценария:** запуск PowerShell с признаками обфускации, например `-enc` / `-encodedcommand`.  
**Что проверяется:** visibility на уровне процессов, анализ command line и базовая endpoint detection logic.  
**Источники:** Sysmon, Windows Client.  
**Практическая ценность:** демонстрирует понимание suspicious execution patterns.

## 3. Suspicious PowerShell download activity
**Суть сценария:** выполнение PowerShell-команд, связанных с загрузкой удаленного содержимого.  
**Что проверяется:** анализ PowerShell activity, подозрительных команд загрузки и возможная корреляция с сетевой активностью.  
**Источники:** Sysmon, PowerShell logs, Suricata.  
**Практическая ценность:** связывает host telemetry и network context в единый use case.

## 4. Office → PowerShell / cmd execution chain
**Суть сценария:** запуск PowerShell или `cmd.exe` из приложений Office или других нетипичных родительских процессов.  
**Что проверяется:** анализ parent-child process relationships и поведенческие детекты.  
**Источники:** Sysmon, Windows Client.  
**Практическая ценность:** показывает более зрелый подход к detection engineering, чем поиск по одному событию.

## 5. Execution from Temp / AppData / user-writable directories
**Суть сценария:** запуск исполняемых файлов или скриптов из пользовательских или временных директорий.  
**Что проверяется:** detection logic на основе нетипичного расположения исполняемых объектов.  
**Источники:** Sysmon, Windows Client.  
**Практическая ценность:** полезный базовый сценарий для поиска suspicious execution.

## 6. Suspicious traffic toward DMZ services
**Суть сценария:** подозрительная или нетипичная сетевая активность в сторону web-сервера в DMZ.  
**Что проверяется:** видимость сетевой активности на стороне IPS и возможность расследования событий, связанных с exposed service.  
**Источники:** Suricata IPS, DMZ web host.  
**Практическая ценность:** демонстрирует работу с сетевыми событиями и роль DMZ в архитектуре.

## 7. Inline IPS alert / blocking demonstration
**Суть сценария:** controlled test traffic, при котором Suricata не только обнаруживает активность, но и демонстрирует работу как IPS.  
**Что проверяется:** разница между detection и prevention, а также корректность расположения IPS в топологии.  
**Источники:** Suricata IPS.  
**Практическая ценность:** показывает, что сеть в лаборатории используется не только для visibility, но и для базового prevention.

## 8. Suspicious account management activity
**Суть сценария:** действия, связанные с изменениями учетных записей, групп или привилегий на Windows Server.  
**Что проверяется:** мониторинг identity-related events и базовых administrative changes.  
**Источники:** Windows Security Logs, Windows Server.  
**Практическая ценность:** добавляет в лабораторию не только endpoint- и network-сценарии, но и identity-focused monitoring.
