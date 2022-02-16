import os
import socket
import sqlite3
import subprocess as sp
from dotenv import load_dotenv
import pandas as pd

from extra.file_task import FileWork


class nmapModule:

    def __init__(self, target=None):
        """
        Func for initialization checking ip address for
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
        load_dotenv()
        self.timeout = os.environ.get('TIMEOUT')
        self.max_retry = os.environ.get('MAX_RETRY')
        self.parallel = os.environ.get('PARALLEL')
        self.rate = os.environ.get('RATE')
        if bool(os.environ.get('DEBUG')):
            self.packet_trace = '--packet-trace'
        else:
            self.packet_trace = ''
        self.optimization_str = f'--max-retries {self.max_retry} --host-timeout {self.timeout} '+ \
                                f'--min-parallelism {self.parallel} --min-rate {self.rate} ' + \
                                    self.packet_trace
        self.port_closed = None
        self.strong_host_down = None
        self.host_down = None
        self.fw = FileWork()
        self.binary_path = self.fw.tmp_storage
        self.sql = sqlite3.connect(self.fw.path_with_data / 'vpn.db')
        self.cur = self.sql.cursor()
        self.vpn_found = False
        self.score = 0
        self.tmp_result = self.fw.tmp_storage / f'{self.target}.txt'
        
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
        self.default_ports = self.default_ports.drop_duplicates(subset=['port'])
        self.default_ports = list(self.default_ports.loc[self.default_ports['common'] == 'FALSE']['port'].values.astype('str'))
        self.ports_str = ', '.join(self.default_ports)
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
        if self.target is None:
            raise ValueError('Please reinit class with correct target!')

    @staticmethod
    def command_exec(command):
        """
        Func for communicate with nmap application via cmd
        :param command:
        :return: result of executing
        """
        return sp.getoutput(command)

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
            self.strong_output = self.command_exec(f'nmap -p {port} -Pn {ipv6} -v {self.target} -oX {self.fw.tmp_storage}')
            self.strong_output = '\n'.join(self.strong_output.split('\n')[2:])
            self.fw.write_in_file(self.tmp_result, self.strong_output)
        self.strong_check_complete = True
        return self.strong_output

    def retrieving_geo(self):
        """
        Retrieving IP geolocation with http://www.geoplugin.com/
        :return: geolocation of target
        """
        return self.command_exec('sudo nmap --script ip-geolocation-geoplugin ' + self.optimization_str + ' ' + self.target + \
            f' -oX {self.fw.tmp_storage}/{self.target}_geo.xml')

    def traceroute_with_geo(self):
        """
        Traceroute information about target IP address
        :return: info path to IP address
        """
        return self.command_exec(f'sudo nmap --traceroute {self.target} ' + self.optimization_str + \
            f' -oX {self.fw.tmp_storage}/{self.target}_traceroute.xml')
        
    def full_info(self):
        """
        Make conclusion about most aspects about host (OS, pattern of ports, 
        type of services on them, etc.) 
        This gives the most large information, but too slow for regular analysis
        """
        self.command_exec(f'sudo nmap -A 185.22.206.72 -oX {self.fw.tmp_storage}/{self.target}_full.xml ' + self.optimization_str)
    
    def ping(self):
        """
        Fast way to find host state
        Use only for host without firewall
        """
        self.command_exec(f'sudo nmap -sn {self.target} \
                            -oX {self.fw.tmp_storage}/{self.target}_ping.xml')
    
    def subnet_discover(self):
        """
        Fast way to discover host with ping probe of subnet.
        Use if hostname of host is not define
        """
        self.subnet = self.target.split('.')
        self.subnet [-1] = '0/24'
        self.subnet = '.'.join(self.subnet)
        self.command_exec(f'sudo nmap {self.subnet} \
                            -oX {self.fw.tmp_storage}/{self.target}_subnet.xml')