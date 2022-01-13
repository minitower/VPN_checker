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
        self.ip = ip
        self.fw = FileWork()
        self.connected_ip = connected_ip
        self.binary_path = self.fw.tmp_storage
        self.sql = sqlite3.connect(r'C:\Users\user\PycharmProjects\VPN_checker\Data_storage\vpn.db')
        self.cur = self.sql.cursor()
        self.score = 0
        self.table_list = ['HTTP proxies',
                           'L2TP/IPsec',
                           'OpenVPN',
                           'SOCKS 5 proxies',
                           'SOCKS 4 proxies',
                           'SSL proxies',
                           'VPN']
        self.cur.execute('select * from vpn_ports;')
        self.default_ports = pd.DataFrame(self.cur.fetchall(), columns=['port', 'protocol', 'common'])
        self.warning_ports = self.default_ports.copy()
        self.default_ports = list(self.default_ports.loc[self.default_ports['common'] == 'FALSE']['port'].values)
        self.scoring_dict = {'open_port': 1,
                             'open_vpn_port': 3,
                             'mistery_port': 0,
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

    def command_exec(self, command):
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
        :param ports: interval of ports to analyse
        :param methods: methods (one or list from [result_intense, result_intense udp,
        result_intense tcp, result_intense no ping, ping, quick,
        traceroot, regular, slow])
        :return: results
        """
        if methods is None:
            methods = ['regular']

        if ports == None:
            ports = self.default_ports

        if type(ports) == int or type(ports) == str:
            ports = list(ports)

        if len(target) > 16:
            ipv6 = '-6'
        else:
            ipv6 = ''
        if 'result_intense' in methods:
            for port in ports:
                result = self.command_exec(f'nmap -p {port} -T4 -A {ipv6} -v {target}')
                with open(self.fw.results + f'\\result_intense\\{target} p {port}.txt', 'a+') as f:
                    f.write(result)

        if 'result_intense udp' in methods:
            for port in ports:
                result = self.command_exec(f'nmap -p {port} -sS -sU -T4 {ipv6} -A -v {target}')
                with open(self.fw.results + f'\\result_intense_upd\\{target} p {port}.txt', 'a+') as f:
                    f.write(result)

        if 'result_intense no ping' in methods:
            for port in ports:
                result = self.command_exec(f'nmap -T4 -A -v -p {port} {ipv6} -Pn {target}')
                with open(self.fw.results + f'\\result_intense_no_ping\\{target} p {port}.txt', 'a+') as f:
                    f.write(result)

        if 'ping' in methods:
            for port in ports:
                result = self.command_exec(f'nmap -sn -p {port} {ipv6} {target}')
                with open(self.fw.results + f'\\result_ping\\{target} p {port}.txt', 'a+') as f:
                    f.write(result)

        if 'quick' in methods:
            for port in ports:
                result = self.command_exec(f'nmap -T4 -F -p {port} {ipv6} {target}')
                with open(self.fw.results + f'\\result_quick\\{target} p {port}.txt', 'a+') as f:
                    f.write(result)

        if 'traceroot' in methods:
            for port in ports:
                result = self.command_exec(f'nmap -sn --traceroute -p {port} {ipv6} {target}')
                with open(self.fw.results + f'\\result_traceroot\\{target} p {port}.txt', 'a+') as f:
                    f.write(result)

        if 'regular' in methods:
            for port in ports:
                result = self.command_exec(f'nmap -p {port} {ipv6} {target}')
                with open(self.fw.results + f'\\result_regular\\{target} p {port}.txt', 'a+') as f:
                    f.write(result)

        if 'slow' in methods:
            for port in ports:
                result = self.command_exec(f'nmap -sS -sU -T4 -A -v {ipv6} -p {port} -PE -PP -PS80,443 -PA3389 '
                                           f'-PU40125 -PY -g 53 --script "default or (discovery and safe)" {target}')
                with open(self.fw.results + f'\\result_large\\{target} p {port}.txt', 'a+') as f:
                    f.write(result)

    def pretty_out(self, file=None, replace=False, wizard=True):
        """
        Func for create output of module more pretty
        :param wizard: Helper with test making. If true - can make design of some extra test for good result
        :param replace: replace file in direction? If False - create new file with suffix pretty
        :param file: path to the file
        :return: string with output nmap
        """
        if file is None:
            raise ValueError('Please, write a file path')
        data = self.fw.read_from_file(file)
        host = file.split('\\')[-1].split(' p ')[0]
        port = file.split('\\')[-1].split(' p ')[-1]
        dir = file.split('\\')[-2]
        header_index = None
        self.preety_data = ''
        if data.find('Host seems down') != -1:
            conclusion_1 = 'В настоящий момент не удается связаться с данной машиной.\nМашина не только не отвечает на ' \
                           'запросы по пингуемым портам, но также и не дала ответа о полчении данных на общедоступные порты\n'
            if wizard:
                conclusion_1 += 'Произведем усиленную проверку (атрибут -Pn)\n'
                self.strong_check()
                conclusion_1 += 'Результаты проверки в конце файла\n'
            print(conclusion_1)
            self.preety_data += conclusion_1
            self.host_down = True
        else:
            conclusion_2 = 'Хост в сети. Существует вероятность того, что он - сервер.\n'
            print(conclusion_2)
            self.preety_data += conclusion_2
            self.host_down = False

        arr = data.split('\n')

        try:
            header_index = arr.index('') + 1
        except ValueError:
            conclusion_3 = 'Скрипт не нашел портов, с которым связн хост. Возможно, что все порты закрыты (либо заняты)\n'
            print(conclusion_3)
            self.preety_data += conclusion_3
            self.port_closed = True

        if header_index:
            n = ' '
            conclusion_4 = 'Найдены следующие открытые порты:'
            self.ports_checker = []
            while n != '':
                i = header_index + 1
                conclusion_4 += f'\n{arr[i]}'
                if len(self.warning_ports.loc[self.warning_ports['port'] ==
                                              int(arr[header_index + 1].split('/')[0])]) != 0 and \
                        len(self.warning_ports.loc[self.warning_ports['port'] ==
                                                   int(arr[header_index + 1].split('/')[0])]) != 0:
                    conclusion_4 += 'порт может принадлежать сервису VPN, однако типичен и для обычных машин\n'
                    if 'filtered' in i:
                        open_port = 0.5 * self.scoring_dict['open_port']
                        self.ports_checker.append(open_port)
                    else:
                        open_port = 1 * self.scoring_dict['open_port']
                        self.ports_checker.append(open_port)
                    self.ports_checker.append(open_port)

                elif len(self.warning_ports.loc[self.warning_ports['port'] ==
                                                int(arr[header_index + 1].split('/')[0])]) != 0:
                    conclusion_4 += 'порт, с уверенностью, принадлежит сервису VPN\n'
                    if 'filtered' in i:
                        open_vpn_port = 0.5 * self.scoring_dict['open_vpn_port']
                        self.ports_checker.append(open_vpn_port)
                    else:
                        open_vpn_port = 1 * self.scoring_dict['open_vpn_port']
                        self.ports_checker.append(open_vpn_port)
                    self.ports_checker.append(open_vpn_port)

                else:
                    conclusion_4 += 'нет официальных данных относительно происхождения порта\n'
                    if 'filtered' in i:
                        mistery_port = 0.5 * self.scoring_dict['mistery_port']
                        self.ports_checker.append(mistery_port)
                    else:
                        mistery_port = 1 * self.scoring_dict['mistery_port']
                        self.ports_checker.append(mistery_port)
                    self.ports_checker.append(mistery_port)
            print(conclusion_4)
            self.preety_data += conclusion_4

        if self.strong_check_complete:
            data = self.fw.read_from_file(self.fw.results + f'\\result_strong\\{host} p {port}.txt')
            arr = data.split('\n')
            if data.find('Host seems down') != -1:
                conclusion_6 = 'Хост с большой долей вероятности отключен от сети Интернет. Скорее всего он - не ' \
                               'VPN/Proxy\n '
                print(conclusion_6)
                self.preety_data += conclusion_6
                self.strong_host_down = True
            else:
                conclusion_7 = 'В результате усиленной проверки хост был обнаружен.\n' \
                               'Однако все еще есть большая вероятность того, что он - не сервер VPN/Proxy\n'
                print(conclusion_7)
                self.preety_data += conclusion_7
                self.strong_host_down = False

            try:
                header_index = arr.index('') + 1
            except ValueError:
                conclusion_5 = 'Скрипт усиленной проверки не нашел портов, с которым связн хост. Скорее всего все ' \
                               'порты закрыты (либо заняты)\n '
                print(conclusion_5)
                self.preety_data += conclusion_5
                self.port_closed = True

            if header_index:
                n = ' '
                conclusion_5 = 'Скриптом усиленной проверки найдены следующие открытые порты:'
                while n != '':
                    i = header_index + 1
                    conclusion_5 += f'\n{arr[i]}'
                    if len(self.warning_ports.loc[self.warning_ports['port'] ==
                                                  int(arr[header_index + 1].split('/')[0])]) != 0 and \
                            len(self.warning_ports.loc[self.warning_ports['port'] ==
                                                       int(arr[header_index + 1].split('/')[0])]) != 0:
                        conclusion_5 += 'порт может принадлежать сервису VPN, однако типичен и для обычных машин\n'
                        if 'filtered' in i:
                            open_port = 0.5 * self.scoring_dict['open_port']
                            self.ports_checker.append(open_port)
                        else:
                            open_port = 1 * self.scoring_dict['open_port']
                            self.ports_checker.append(open_port)

                    elif len(self.warning_ports.loc[self.warning_ports['port'] ==
                                                    int(arr[header_index + 1].split('/')[0])]) != 0:
                        conclusion_5 += 'порт, с уверенностью, принадлежит сервису VPN\n'
                        if 'filtered' in i:
                            open_vpn_port = 0.5 * self.scoring_dict['open_vpn_port']
                            self.ports_checker.append(open_vpn_port)
                        else:
                            open_vpn_port = 1 * self.scoring_dict['open_vpn_port']
                            self.ports_checker.append(open_vpn_port)

                    else:
                        conclusion_5 += 'нет официальных данных относительно происхождения порта\n'
                        if 'filtered' in i:
                            mistery_port = 0.5 * self.scoring_dict['mistery_port']
                            self.ports_checker.append(mistery_port)
                        else:
                            mistery_port = 1 * self.scoring_dict['mistery_port']
                            self.ports_checker.append(mistery_port)
                print(conclusion_5)
                self.preety_data += conclusion_5

        self.scorring()
        if self.score >= 10:
            final_conclusion = 'Скорринг выше среднего, есть вероятность наличия VPN'
            self.preety_data += final_conclusion
            self.fw.write_in_file(self.fw.final_results+f"\\Don't_sure\\"
                                                        f"preety_data_{dir}_{host}_{port}.txt", self.preety_data)
        elif self.score >= 20:
            final_conclusion = 'Скорринг высокий, велика вероятность наличия VPN'
            self.preety_data += final_conclusion
            self.fw.write_in_file(self.fw.final_results+f"\\Likely_VPN\\"
                                                        f"preety_data_{dir}_{host}_{port}.txt", self.preety_data)
        else:
            final_conclusion = 'Скоринг низкий, вероятность наличия VPN мала'
            self.preety_data += final_conclusion
            self.fw.write_in_file(self.fw.final_results+f"\\Likely_non-VPN\\"
                                                        f"preety_data_{dir}_{host}_{port}.txt", self.preety_data)

    def db_search_IP(self, target, table_list=['all']):
        """
        Func for most clear and simple methods - try to find
        target IP in free VPN database
        :param target: IP address of host
        :param table_list: list, if all - search from all tables
        :return: bool, if True - VPN
        """
        if table_list == ['all']:
            table_list = self.table_list
        for i in table_list:
            cur = self.sql.cursor()
            cur.execute(f'SELECT * FROM "{i}" WHERE "ip" == {target}')
            if len(cur.fetchall()) >= 0:
                self.vpn_found = True
                print(f'{self.fw.WARNING} FOUND VPN: {target}, TABLE {}{self.fw.ENDC}')
                break
        if not self.vpn_found:
            target = socket.gethostbyaddr(target)
            for i in table_list:
                cur = self.sql.cursor()
                cur.execute(f'SELECT * FROM "{i}" WHERE "ip" == {target}')
                if len(cur.fetchall()) >= 0:
                    self.vpn_found = True
                    print(f'{self.fw.WARNING} FOUND VPN: {target}, TABLE {}{self.fw.ENDC}')
                    break
        return self.vpn_found

    def hostname_analyse(self, target):
        """
        Func for make predict about host to her domain name in public DNS
        :return: predict
        """
        hostname = socket.gethostbyaddr(target)
        if ['amasonaws', 'elatomono', 'vps', 'vpn', 'ppp',
            'server', 'secureserver', 'telcom', 'google', 'host'] in hostname:
            print(f'Strange name... {target} ==> {hostname}')
            return (target, hostname)

    def scorring(self):
        """
        Func for summarise all parameters of automatate script
        :return: self.score
        """
        if self.host_down:
            self.score += self.scoring_dict['host_down']
        else:
            self.score += self.scoring_dict['host_up']
        if self.strong_host_down:
            self.score += self.scoring_dict['host_down']
        else:
            self.score += self.scoring_dict['host_up']
        if self.port_closed:
            self.score += self.scoring_dict['closed']
        self.score = sum(self.ports_checker)
        return self.score

    def strong_check(self, target=None, ports=None):
        """
        Func for check hosts machine (PC or server)
        :param target: ip of machine
        :param ports: searchable ports
        :return: file with result
        """
        if ports == None:
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
