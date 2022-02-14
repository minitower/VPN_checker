# VPN_checker 
#####Based on nmap



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
