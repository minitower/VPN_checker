import os
import sqlite3
from typing import List

from file_task import FileWork
import subprocess as sp
import traceback
import warnings
import requests
import shutil
import pandas as pd
import socket


class nmapModule:

    def __init__(self, ip=None, connected_ip=None, nmap_install=False):
        """
        Func for initialisation checking ip address for
        1) VPN by 2 method: ping VPN port or connect to VPN ports
        2) location of IP (by domain)
        3) check for time of up host in Ethernet
        :param ip: str of list of str - if None - just init
        :param connected_ip: if True - try to find same open ports or sockets
        """
        self.ports_checker = []
        self.port_closed = None
        self.strong_host_down = None
        self.host_down = None
        self.ip = ip
        self.fw = FileWork()
        self.connected_ip = connected_ip
        self.binary_path = self.fw.tmp_storage
        self.sql = sqlite3.connect(r'C:\Users\user\PycharmProjects\VPN_checker\Data_storage\vpn.db')
        self.cur = self.sql.cursor()
        self.vpn_found = False
        self.score = 0
        self.table_list = ['HTTP_proxies',
                           'L2TP_IPsec',
                           'SOCKS_5',
                           'SOCKS_4',
                           'SSL',
                           'VPN']
        self.strong_check_complete = False
        self.cur.execute('select * from vpn_ports;')
        self.default_ports = pd.DataFrame(self.cur.fetchall(), columns=['port', 'protocol', 'common'])
        self.warning_ports = self.default_ports.copy()
        self.default_ports = list(self.default_ports.loc[self.default_ports['common'] == 'FALSE']['port'].values)
        self.scoring_dict = {'open_port': 1,
                             'open_vpn_port': 3,
                             'filtered_port': 2,
                             'closed': -3,
                             'host_down': -5,
                             'host_up': 3}
        if not nmap_install:
            if self.check() == 2:
                if os.system('nmap') == 1:
                    accept = input('To run this class you need to install nmap toolkit. Install(Y/n)?')
                    if accept in ['', ' ', 'Y', 'y']:
                        self.nmap_install()
        else:
            self.nmap_install()

    def check(self):
        """
        Func for checking the install params
        :return: True if can install, else False
        """
        try:
            open(self.binary_path)
            permission = True
        except PermissionError:
            permission = False
        else:
            warnings.warn('Current user has no permission to write in {}'.format(self.binary_path))
            self.binary_path = input('Please input new path for downloads: ')
            self.check()
        if os.path.exists(self.binary_path):
            path = True
        else:
            warnings.warn("Path {} didn't exist".format(self.binary_path))
            self.binary_path = input('Please input new path for downloads: ')
            self.check()
            path = False
        return path + permission

    def nmap_install(self):
        """
        Func for setup.py and install nmap on machine
        :return: None
        """
        if os.name == 'nt':
            print('Windows installer started!')
            r = requests.get('https://nmap.org/dist/nmap-7.92-setup.exe', stream=True)
            r.raw.decode_content = True
            with open(self.binary_path + '\\setup.exe', 'wb') as f:
                shutil.copyfileobj(r.raw, f)
            # print('Connection refused, reconnect')
            #    self.nmap_install()
            print('setup.exe succsesful downloaded')

            try:
                print('Start install process...')
                hostname = sp.run(['hostname'], stdout=sp.PIPE).stdout.decode('utf-8')
                hostname.replace('\n', '')
                hostname.replace('\r', '')
                sp.getoutput(r'C:\Users\user\PycharmProjects\VPN_checker\Tmp_storage\setup.exe')
            except WindowsError:
                traceback.print_exc()

    @staticmethod
    def command_exec(command):
        """
        Func for communicate with nmap application via cmd
        :param command:
        :return: result of executing
        """
        return sp.getoutput(command)

    def windows_default_scan(self, target=None, ports=None, methods=None):
        """
        Func for pinging ports of init IP address
        :param target: IP of target to analyse
        :param ports: interval of ports to analyse or all
        :param methods: methods (one or list from [result_intense, result_intense udp,
        result_intense tcp, result_intense no ping, ping, quick,
        traceroot, regular, slow])
        :return: results
        """
        if methods is None:
            methods = ['result_regular']

        if ports is None:
            ports = self.default_ports

        if ports == 'all':
            ports = '1-47823'

        if type(ports) == int or type(ports) == str:
            ports = list(ports)

        if len(target) > 16:
            ipv6 = '-6'
        else:
            ipv6 = ''

        if 'result_intense' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -p {port} -T4 -A {ipv6} -v {target}')
                with open(self.fw.results + f'\\result_intense\\{target}.txt', 'w') as f:
                    f.write(self.output)
                return self.output

        if 'result_intense_udp' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -p {port} -sS -sU -T4 {ipv6} -A -v {target}')
                with open(self.fw.results + f'\\result_intense_upd\\{target}.txt', 'w') as f:
                    f.write(self.output)
                return self.output

        if 'result_intense_no_ping' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -T4 -A -v -p {port} {ipv6} -Pn {target}')
                with open(self.fw.results + f'\\result_intense_no_ping\\{target}.txt', 'w') as f:
                    f.write(self.output)
                return self.output

        if 'result_ping' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -sn -p {port} {ipv6} {target}')
                with open(self.fw.results + f'\\result_ping\\{target}.txt', 'w') as f:
                    f.write(self.output)
                return self.output

        if 'result_quick' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -T4 -F -p {port} {ipv6} {target}')
                with open(self.fw.results + f'\\result_quick\\{target}.txt', 'w') as f:
                    f.write(self.output)
                return self.output

        if 'result_traceroot' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -sn --traceroute -p {port} {ipv6} {target}')
                with open(self.fw.results + f'\\result_traceroot\\{target}.txt', 'w') as f:
                    f.write(self.output)
                return self.output

        if 'result_regular' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -p {port} {ipv6} {target}')
                with open(self.fw.results + f'\\result_regular\\{target}.txt', 'w') as f:
                    f.write(self.output)
                return self.output

        if 'result_large' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -sS -sU -T4 -A -v {ipv6} -p {port} -PE -PP -PS80,443 -PA3389 '
                                           f'-PU40125 -PY -g 53 --script "default or (discovery and safe)" {target}')
                with open(self.fw.results + f'\\result_large\\{target}.txt', 'w') as f:
                    f.write(self.output)
                return self.output

    def db_search_IP(self, target, table_list=None):
        """
        Func for most clear and simple methods - try to find
        target IP in free VPN database
        :param target: IP address of host
        :param table_list: list, if all - search from all tables
        :return: bool, if True - VPN
        """
        if table_list is None:
            table_list = ['all']
        if table_list == ['all']:
            table_list = self.table_list
        for i in table_list:
            cur = self.sql.cursor()
            cur.execute('SELECT * FROM ' + i + ' WHERE ip == "' + target + '";')
            if len(cur.fetchall()) > 0:
                self.vpn_found = True
                print(f'{self.fw.WARNING} FOUND VPN: {target}{self.fw.ENDC}')
                return self.vpn_found
        if not self.vpn_found:
            try:
                target = socket.gethostbyaddr(target)
                if type(target) == tuple:
                    target = target[0]
                for i in table_list:
                    cur = self.sql.cursor()
                    cur.execute('SELECT * FROM ' + i + ' WHERE ip == "' + target + '";')
                    if len(cur.fetchall()) > 0:
                        self.vpn_found = True
                        print(f'{self.fw.WARNING} FOUND VPN: {target}{self.fw.ENDC}')
                        return self.vpn_found
            except socket.herror:
                print(f"{self.fw.WARNING} Target didn't found hostname in localhost DNS {self.fw.ENDC}")
                return self.vpn_found

    def hostname_analyse(self, target):
        """
        Func for make predict about host to her domain name in public DNS
        :return: predict
        """
        hostname = socket.gethostbyaddr(target)
        if ['cmcti', 'linode', 'static', 'your-server', 'clients',
            'dynamic', 'sl-reverse', 'quantum', 'broadband', 'vnpt',
            'nidix', 'netbynet', 'totalplay', 'vps', 'ertelecom', 'altair',
            'megared', 'hanastar', 'oxentenet', 'rfconnect'] in hostname:
            print(f'Strange name... {target} ==> {hostname}')
            return target, hostname

    def strong_check(self, target=None, ports=None):
        """
        Func for check hosts machine (PC or server)
        :param target: ip of machine
        :param ports: searchable ports
        :return: file with result
        """
        if ports is None:
            ports = self.default_ports

        if type(ports) == int or type(ports) == str:
            ports = list(ports)

        if len(target) > 16:
            ipv6 = '-6'
        else:
            ipv6 = ''

        for port in ports:
            result = self.command_exec(f'nmap -p {port} -Pn {ipv6} -v {target}')
            with open(self.fw.results + f'\\result_strong_search\\{target} p {port}.txt', 'a+') as f:
                f.write(result)
        self.strong_check_complete = True
        return result
