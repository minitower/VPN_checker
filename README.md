# VPN_checker 

Main mission: get program, which can count probability of IP address is belongs to VPN service
Script use Nmap software and contains next method of analysis:

1) Port scan on most common for VPN services ports (OpenVPN, L2TP/IP, etc);
2) Traceroot to IP address (help to find hub with strange activity);
3) Geolocation of IP address (if location other then expected in script - keep research);
4) OS detection (most servers of VPN - on Linux, most desktop - on Windows);
5) Ping of IP address (use for find up host in IP addresses data base).

**Remember, script can get good accurancy only for IP addresses with small time interval (1-2 days)**
This limitation formed due to IPv4 dinamic registration (address lease term is sometimes several hours, so some host can use DDNS)

## Getting Started

Download links:

SSH clone URL: ssh://git@git.jetbrains.space/minitower/vpn-checker/VPN_checker.git

HTTPS clone URL: https://git.jetbrains.space/minitower/vpn-checker/VPN_checker.git 

First to all install **nmap** module for your OS in local machine. You can download this application on https://nmap.org/.

## Prerequisites

After **installing nmap** in local machine (and Npcap, if needed) you must check administrative rights
on machine and correct configuration for nmap scripts. This module parse following scripts

```
script ip-geolocation-geoplugin
script traceroute-geolocation
script whois-ip
```

This script must locate on: **$NMAP_PATH$/scripts**. If scripts didn't upload automatically, please install and 
move this files on right folder.

## Deployment

Script try to do all necessary by yourself (install nmap, check and download script for check etc.), but if
you face a problem you can reinstall nmap, close firewall (for loopback), run script with administrative permissions,
or build .env file with necessary configuration.
