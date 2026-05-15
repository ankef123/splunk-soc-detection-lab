# Архитектура лаборатории

![topology](/screenshots/topology.png)

| Host | Interfaces | Default Gateway | Notes |
|---|---|---|---|
| **Kali** | `e0` → NET → `172.16.10.10/24` | `172.16.10.1` | Attack simulation host |
| **ISP-EDGE-RTR** | `Gi0/0` → NET → `172.16.10.1/24`  <br> `Gi0/1` → link to Suricata outside → `no IP`  <br> `Gi0/2` → INTERNET → `DHCP` | `DHCP` on `Gi0/2` | Edge router with NAT and internet access |
| **Suricata IPS** | `ens3` → IPS outside/data → `no IP`  <br> `ens4` → IPS inside/data → `no IP`  <br> `ens5` → MGMT → `10.10.20.50/24` | `10.10.20.1` | Inline IPS with dedicated management interface |
| **R1** | `Gi0/0` → link from Suricata inside → `no IP`  <br> `Gi0/1.10` → MGMT VLAN 10 → `10.10.20.1/24`  <br> `Gi0/1.20` → LAN VLAN 20 → `10.10.10.1/24`  <br> `Gi0/2` → DMZ → `172.16.20.1/24` | - | Inter-VLAN and inter-zone routing |
| **S1** | `VLAN 10 SVI` → MGMT → `10.10.20.2/24`  <br> `VLAN 20 SVI` → LAN → `10.10.10.2/24` | `10.10.20.1` / `10.10.10.1` | Optional switch management IPs |
| **Splunk** | `e0` → MGMT → `10.10.20.10/24`  <br> `e1` → OOB-ACCESS → `192.168.216.10/24` | `10.10.20.1` | SIEM, accessible from MGMT and real laptop |
| **Admin Workstation** | `e0` → MGMT → `10.10.20.20/24` | `10.10.20.1` | Windows admin workstation / jump host |
| **WinServer** | `e0` → LAN → `10.10.10.10/24` | `10.10.10.1` | AD + DNS + authentication telemetry |
| **WinClient** | `e0` → LAN → `10.10.10.20/24` | `10.10.10.1` | Endpoint telemetry source |
| **Web Server** | `e0` → DMZ → `172.16.20.10/24`  <br> `e1` → OOB-ACCESS → `192.168.216.30/24` | `172.16.20.1` | DMZ web service with direct admin access from real laptop |

Лаборатория спроектирована как небольшая enterprise-like среда с несколькими зонами:

- **NET** — внешняя / attacker-зона
- **DMZ** — зона с вынесенным web-сервисом
- **LAN** — внутренняя сеть с рабочей станцией и Windows Server
- **MGMT** — management / monitoring сегмент

### Ключевые узлы

- **Splunk Enterprise** — центральная SIEM
- **Windows Client** — источник endpoint-телеметрии
- **Windows Server** — источник authentication и infrastructure-телеметрии
- **Suricata IPS** — inline-сетевой контроль и источник network alerts
- **Linux Web Server (DMZ)** — внешний сервис для web/network-сценариев
- **Kali Linux** — хост для controlled attack simulation
- **Admin host** — узел управления внутри MGMT-сегмента

### Архитектурные решения

- Splunk вынесен в отдельный **management-сегмент**
- web-сервер расположен в **DMZ**
- Windows Client и Windows Server находятся в **LAN**
- **Suricata размещена inline как IPS** между внешней зоной и внутренней маршрутизацией
- **MGMT и LAN изолированы через VLAN**

Такая структура делает лабораторию значительно более реалистичной, чем обычная “плоская” сеть, и позволяет корректнее строить сценарии мониторинга и расследования.