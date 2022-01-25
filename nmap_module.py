import os
import shutil
import socket
import sqlite3
import subprocess as sp
import traceback
import warnings

import pandas as pd
import requests

from file_task import FileWork


class nmapModule:

    def __init__(self, target=None, nmap_install=False):
        """
        Func for initialisation checking ip address for
        1) VPN by 2 method: ping VPN port or connect to VPN ports
        2) location of IP (by domain)
        3) check for time of up host in Ethernet
        :param target: str of list of str - if None - raise ValueError
        :param nmap_install: if True - check the installation of nmap in machine
        and install if needed; else pass the installation check and installation
        """
        self.all_country_trace = None
        self.trace = None
        self.owner = None
        self.socks_port = None
        self.geolocation = None
        self.target = target
        self.strong_output = None
        self.output = None
        self.ports_checker = []
        self.port_closed = None
        self.strong_host_down = None
        self.host_down = None
        self.fw = FileWork()
        self.binary_path = self.fw.tmp_storage
        self.sql = sqlite3.connect(r'C:\Users\user\PycharmProjects\VPN_checker\Data_storage\vpn.db')
        self.cur = self.sql.cursor()
        self.vpn_found = False
        self.score = 0
        self.tmp_result = self.fw.tmp_storage + f'\\{self.target}.txt'
        with open(self.tmp_result, 'w') as f:
            f.write('Library for VPN check in ip address')
            print('Library for VPN check in ip address')
            f.write(r'''
     _   _ __  __          _____   __      _______  _   _    _____ _    _ ______ _____ _  ________ _____  
    | \ | |  \/  |   /\   |  __ \  \ \    / /  __ \| \ | |  / ____| |  | |  ____/ ____| |/ /  ____|  __ \ 
    |  \| | \  / |  /  \  | |__) |  \ \  / /| |__) |  \| | | |    | |__| | |__ | |    | ' /| |__  | |__) |
    | . ` | |\/| | / /\ \ |  ___/    \ \/ / |  ___/| . ` | | |    |  __  |  __|| |    |  < |  __| |  _  / 
    | |\  | |  | |/ ____ \| |         \  /  | |    | |\  | | |____| |  | | |___| |____| . \| |____| | \ \ 
    |_| \_|_|  |_/_/    \_\_|          \/   |_|    |_| \_|  \_____|_|  |_|______\_____|_|\_\______|_|  \_\
                                                                                                       
                                                                                                       ''')
            print(r'''
     _   _ __  __          _____   __      _______  _   _    _____ _    _ ______ _____ _  ________ _____  
    | \ | |  \/  |   /\   |  __ \  \ \    / /  __ \| \ | |  / ____| |  | |  ____/ ____| |/ /  ____|  __ \ 
    |  \| | \  / |  /  \  | |__) |  \ \  / /| |__) |  \| | | |    | |__| | |__ | |    | ' /| |__  | |__) |
    | . ` | |\/| | / /\ \ |  ___/    \ \/ / |  ___/| . ` | | |    |  __  |  __|| |    |  < |  __| |  _  / 
    | |\  | |  | |/ ____ \| |         \  /  | |    | |\  | | |____| |  | | |___| |____| . \| |____| | \ \ 
    |_| \_|_|  |_/_/    \_\_|          \/   |_|    |_| \_|  \_____|_|  |_|______\_____|_|\_\______|_|  \_\
                                                                                                       
                                                                                                       ''')
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
                             'host_up': 3,
                             'non-Russia geo': 3,
                             'strange_hostname': 1,
                             'strange_owner': 2,
                             '3 or more country in traceroute': 3}
        if not nmap_install:
            if self.check() == 2:
                if os.system('nmap') == 1:
                    accept = input('To run this class you need to install nmap toolkit. Install(Y/n)?')
                    if accept in ['', ' ', 'Y', 'y']:
                        self.nmap_install()
        else:
            self.nmap_install()
        if self.target is None:
            raise ValueError('Please reinit class with correct target!')

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

    def windows_default_scan(self, ports=None, methods=None):
        """
        Func for pinging ports of init IP address
        :param ports: interval of ports to analyse or all
        :param methods: methods (one or list from [result_intense, result_intense udp,
        result_intense tcp, result_intense no ping, ping, quick,
        traceroute, regular, slow])
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

        if len(self.target) > 16:
            ipv6 = '-6'
        else:
            ipv6 = ''

        if 'result_intense' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -p {port} -T4 -A {ipv6} -v {self.target}')
                self.output = '\n'.join(self.output.split('\n')[2:])
                self.fw.write_in_file(self.tmp_result, '\n' + self.output)
                return self.output

        if 'result_intense_udp' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -p {port} -sS -sU -T4 {ipv6} -A -v {self.target}')
                self.output = '\n'.join(self.output.split('\n')[2:])
                self.fw.write_in_file(self.tmp_result, '\n' + self.output)
                return self.output

        if 'result_intense_no_ping' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -T4 -A -v -p {port} {ipv6} -Pn {self.target}')
                self.output = '\n'.join(self.output.split('\n')[2:])
                self.fw.write_in_file(self.tmp_result, '\n' + self.output)
                return self.output

        if 'result_ping' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -sn -p {port} {ipv6} {self.target}')
                self.output = '\n'.join(self.output.split('\n')[2:])
                self.fw.write_in_file(self.tmp_result, '\n' + self.output)
                return self.output

        if 'result_quick' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -T4 -F -p {port} {ipv6} {self.target}')
                self.output = '\n'.join(self.output.split('\n')[2:])
                self.fw.write_in_file(self.tmp_result, '\n' + self.output)
                return self.output

        if 'result_traceroute' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -sn --traceroute -p {port} {ipv6} {self.target}')
                self.output = '\n'.join(self.output.split('\n')[2:])
                self.fw.write_in_file(self.tmp_result, '\n' + self.output)
                return self.output

        if 'result_regular' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -p {port} {ipv6} {self.target}')
                self.output = '\n'.join(self.output.split('\n')[2:])
                self.fw.write_in_file(self.tmp_result, '\n' + self.output)
                return self.output

        if 'result_large' in methods:
            for port in ports:
                self.output = self.command_exec(f'nmap -sS -sU -T4 -A -v {ipv6} -p {port} -PE -PP -PS80,443 -PA3389 '
                                                f'-PU40125 -PY -g 53 '
                                                f'--script "default or (discovery and safe)" {self.target}')
                self.output = '\n'.join(self.output.split('\n')[2:])
                self.fw.write_in_file(self.tmp_result, '\n' + self.output)
                return self.output

    def db_search_IP(self, table_list=None):
        """
        Func for most clear and simple methods - try to find
        target IP in free VPN database
        :param table_list: list, if all - search from all tables
        :return: bool, if True - VPN
        """
        if table_list is None:
            table_list = ['all']
        if table_list == ['all']:
            table_list = self.table_list
        try:
            target_hostname = socket.gethostbyaddr(self.target)[0]
        except socket.herror:
            print(f"{self.fw.WARNING} Target didn't found hostname in localhost DNS {self.fw.ENDC}")
            target_hostname = None
        for i in table_list:
            cur = self.sql.cursor()
            if target_hostname is not None:
                cur.execute(
                    'SELECT * FROM ' + i + ' WHERE ip == "' + self.target + '" or ip == "' + target_hostname + '" ;')
            else:
                cur.execute('SELECT * FROM ' + i + ' WHERE ip == "' + self.target + '" ;')
            if len(cur.fetchall()) > 0:
                self.vpn_found = True
                print(f'{self.fw.WARNING} FOUND VPN: {self.target}{self.fw.ENDC}')
                return self.vpn_found

    def hostname_analyse(self):
        """
        Func for make predict about host to her domain name in public DNS
        :return: predict
        """
        try:
            hostname = socket.gethostbyaddr(self.target)[0]
            self.fw.write_in_file(self.tmp_result, f'TARGET HOSTNAME: {hostname}')
            if hostname in ['cmcti', 'linode', 'static', 'your-server', 'clients',
                            'dynamic', 'sl-reverse', 'quantum', 'broadband', 'vnpt',
                            'nidix', 'netbynet', 'totalplay', 'vps', 'ertelecom', 'altair',
                            'megared', 'hanastar', 'oxentenet', 'rfconnect']:
                print(f'Strange name... {self.target} ==> {hostname}')
                self.fw.write_in_file(self.tmp_result, f'TARGET HOSTNAME: {hostname}')
                self.score += 1
                return self.target, hostname
        except socket.herror:
            print(f"{self.fw.WARNING} Target didn't found hostname in localhost DNS {self.fw.ENDC}")
            print(f"Try find via nmap module")
            self.fw.write_in_file(self.tmp_result, f"{self.fw.WARNING} Target didn't found hostname "
                                                   f"in localhost DNS {self.fw.ENDC}")

            return self.target, None

    def strong_check(self, ports=None):
        """
        Func for check hosts machine (PC or server)
        :param ports: searchable ports
        :return: file with result
        """
        if ports is None:
            ports = self.default_ports

        if type(ports) == int or type(ports) == str:
            ports = list(ports)

        if len(self.target) > 16:
            ipv6 = '-6'
        else:
            ipv6 = ''

        for port in ports:
            self.strong_output = self.command_exec(f'nmap -p {port} -Pn {ipv6} -v {self.target}')
            self.strong_output = '\n'.join(self.strong_output.split('\n')[2:])
            self.fw.write_in_file(self.tmp_result, self.strong_output)
        self.strong_check_complete = True
        return self.strong_output

    def retrieving_geo(self):
        """
        Retrieving IP geolocation with http://www.geoplugin.com/
        :return: geolocation of target
        """
        self.geolocation = self.command_exec(f'cd C:\\Program Files (x86)\\Nmap && '
                                             f'nmap --script ip-geolocation-geoplugin {self.target}')
        if self.geolocation.find(', try -Pn'):
            self.geolocation = self.command_exec(f'cd C:\\Program Files (x86)\\Nmap && '
                                                 f'nmap -Pn --script ip-geolocation-geoplugin {self.target}')
        arr_values = []
        for i in self.geolocation.split('\n'):
            if len(i) > 0 and i[0] == '|' and len(arr_values) == 0:
                arr_values.append(f'coordinates: {i.replace("| ip-geolocation-geoplugin: coordinates: ", "")}')
            elif len(i) > 0 and i[0] == '|' and len(arr_values) != 0:
                arr_values.append(f'location: {i.replace("|_location: ", "")}')
        arr_values.insert(0, '\n')
        if arr_values[2] != 'Russia':
            self.score += 5
            print(f'{self.fw.WARNING}FIND FOREIGN IP ADDRESS {self.target}'
                  f'{self.fw.ENDC}')
        self.fw.write_in_file(self.tmp_result, f'\nIP ADDRESS LOCATION: {arr_values[2]}, '
                                               f'\nCOORDINATES: {arr_values[1]}')
        return arr_values

    def whois_ip_nmap(self, country='RU'):
        """
        Func for find owner of this IP address. Owner from other country,
        city etc. can be a signal for VPN
        :return: info about owner of IP address
        """
        self.owner = self.command_exec(f'cd C:\\Program Files (x86)\\Nmap && '
                                       f'nmap {self.target} --script whois-ip')
        if self.owner.find(', try -Pn'):
            self.owner = self.command_exec(f'cd C:\\Program Files (x86)\\Nmap && '
                                           f'nmap {self.target} -Pn --script whois-ip')
        arr_values = []
        for i in self.owner.split('\n'):
            if len(i) > 0:
                if i[0] == '|' and i[2] != 'w':
                    arr_values.append(i.replace('|_', '').replace('| ', ''))
        arr_values.insert(0, '\n')
        self.fw.write_in_file(self.tmp_result, '\n'.join(arr_values))
        return arr_values

    def traceroute_with_geo(self):
        """
        Traceroute information about target IP address
        :return: info path to IP address
        """
        self.trace = self.command_exec(f'cd C:\\Program Files (x86)\\Nmap && '
                                       f'nmap --traceroute --script traceroute-geolocation {self.target}')
        if self.trace.find(', try -Pn'):
            self.trace = self.command_exec(f'cd C:\\Program Files (x86)\\Nmap && '
                                           f'nmap --traceroute -Pn --script traceroute-geolocation {self.target}')
        arr_values = []
        for i in self.trace.split('\n'):
            if len(i) > 0:
                if i[0] == '|' and i[2] != 't':
                    arr_values.append(i.replace('|_  ', '').replace('|   ', ''))
        arr_values.insert(0, '\n')
        self.fw.write_in_file(self.tmp_result, '\n'.join(arr_values))
        return arr_values
