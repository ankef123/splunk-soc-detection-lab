# Recon / scanning
## Nmap SYN Scan
    alert tcp any any -> $HOME_NET any (flags:S; msg:"LAB Nmap SYN scan detected"; threshold:type both, track by_src, count 5, seconds 10; sid:1000003; rev:1;)
## Ping sweep
    alert icmp any any -> $HOME_NET any (msg:"LAB ICMP sweep detected"; threshold:type both, track by_src, count 10, seconds 5; sid:1000004; rev:1;)

# Web атаки
## Попытка доступа к admin
    alert http any any -> $HOME_NET any (msg:"LAB Access to /admin detected"; content:"/admin"; http_uri; sid:1000005; rev:1;)
## Попытка API доступа
    alert http any any -> $HOME_NET any (msg:"LAB API access detected"; content:"/api"; http_uri; sid:1000006; rev:1;)
## SQL Injection (простая сигнатура)
    alert http any any -> $HOME_NET any (msg:"LAB SQL Injection attempt"; content:"' OR 1=1"; nocase; sid:1000007; rev:1;)

# Brute force (SSH)
    alert tcp any any -> $HOME_NET 22 (msg:"LAB Possible SSH brute force"; threshold:type both, track by_src, count 5, seconds 60; sid:1000008; rev:1;)

# Suspicious DNS
    alert dns any any -> any any (msg:"LAB Suspicious DNS query"; content:"evil.com"; nocase; sid:1000009; rev:1;)

# ICMP flood
    alert icmp any any -> $HOME_NET any (msg:"LAB ICMP flood detected"; threshold:type both, track by_src, count 20, seconds 3; sid:1000010; rev:1;)

# 03_powershell_download
    alert http any any -> any any (
    msg:"LAB PowerShell Script Download";
    flow:established,to_server;
    http.method; content:"GET"; nocase;
    http.uri; content:".ps1"; nocase;
    classtype:trojan-activity;
    sid:1000011;
    rev:1;
    )