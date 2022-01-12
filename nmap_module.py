import os

import nmap


class Ip_Tracking:

    def __init__(self, ip=None, connected_ip=None):
        """
        Func for initialisation checking ip address for
        1) VPN by 2 method: ping VPN port or connect to VPN ports
        2) location of IP (by domain)
        3) check for time of up host in Ethernet
        :param ip: str of list of str - if None - just init
        :param connected_ip: if True - try to find same open ports or sockets
        """
        self.ip = ip
        self.connected_ip = connected_ip
        self.np = nmap.PortScanner()
        if self.connected_ip:
            print(f'Try to find same patterns via {self.ip} == {self.connected_ip}')
            self.con_mode = True
        else:
            print(f'IP {self.ip} ready to analyse!')

    def ping_ports(self, ports=None, methods=['default']):
        """
        Func for pinging ports of init IP address
        :param ports: interval of ports to analyse
        :param methods: methods (one or list from [intense, intense udp,
        intense tcp, intense no ping, ping, quick,
        traceroot, regular, slow])
        :return: results
        """
        if 'intense' in methods:
            os.system('nmap -T4 -A -v 85.26.235.41')
        if 'intense udp' in methods:
            os.system('nmap -sS -sU -T4 -A -v 85.26.235.41')
        if 'intense tcp' in methods:
            os.system('nmap -p 1-65535 -T4 -A -v 85.26.235.41')
        if 'intense no ping' in methods:
            os.system('nmap -T4 -A -v -Pn 85.26.235.41')
        if 'ping' in methods:
            os.system('nmap -sn 85.26.235.41')
        if 'quick' in methods:
            os.system('nmap -T4 -F 85.26.235.41')
        if 'traceroot' in methods:
            os.system('nmap -sn --traceroute 85.26.235.41')
        if 'regular' in methods:
            os.system('nmap 85.26.235.41')
        if 'slow' in methods:
            os.system('nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 '
                      '-PU40125 -PY -g 53 --script "default or (discovery and safe)" 85.26.235.41')