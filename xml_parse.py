from cProfile import label
from email import message
import warnings
import xml.etree.ElementTree as ET
import os

from datetime import datetime

from attr import attrib
from extra.file_task import FileWork
from pathlib import Path


class XML_parse:
    
    def __init__(self, target):
        """
        Class for pars XML from nmap_module output.
        Class automatate upload all trees, which available in Tmp_storage

        Args:

            target (type: str): IP address of host with files in Tmp_storage
        """
        self.fw = FileWork()
        self.target = target
        lst_target_files = []
        lst_files = [i for i in os.walk(self.fw.tmp_storage)][-1][-1]
        self.dict_trees = {}
        
        with open(f'final/{self.target}.txt', 'w') as f: # to be sure: file will be empty
            pass

        for i in lst_files:
            if i.find(target) != -1:
                lst_target_files.append(i)
        
        for i in lst_target_files:
            self.dict_trees.update({i.split('_')[-1].split('.')[0]:
                                        ET.parse(self.fw.tmp_storage / Path(i))})
        
        print('Found next methods' + '\n'.join(self.dict_trees.keys()))
        self.finalize()

    def ping_parse(self):
        """
        Func for pars XML tree of "ping" file
        """
        tree = self.dict_trees['ping']
        root  = tree.getroot()
        host = list(root)[2]
        runstats = list(root)[-1]
        
        self.dict_ping_info = {
            'start time': root.items()[root.keys().index('start')][-1], 
            'state': list(host)[0].attrib['state'], 
            'hostname': list(list(host)[2])[0].attrib['name'], 
            'srtt': list(host)[3].attrib['srtt'], 
            'rttvar': list(host)[3].attrib['rttvar'],
            'end time': list(runstats)[0].attrib['time'],
            'elapsed': list(runstats)[0].attrib['elapsed']
        }
        
        # For pretty time format
        time = datetime.utcfromtimestamp(int(self.dict_ping_info  
                    ['start time'])).strftime("%y-%m-%d %H:%M:%S")
        self.dict_ping_info.update({'pretty_start_time': time})
        time = datetime.utcfromtimestamp(int(self.dict_ping_info
                    ['end time'])).strftime("%y-%m-%d %H:%M:%S")
        self.dict_ping_info.update({'pretty_end_time': time})
        
        self.ping_message = f"""
        ------------PING REPORT------------
        START AT: {self.dict_ping_info['pretty_start_time']}
        HOST STATE: {self.dict_ping_info['state']}
        HOSTNAME: {self.dict_ping_info['hostname']}
        SMOOTHED I/O TIME: {self.dict_ping_info['srtt']}
        VARIANCE OF TRIP: {self.dict_ping_info['rttvar']}
        END AT: {self.dict_ping_info['pretty_end_time']}
        ELAPSED: {self.dict_ping_info['elapsed']} s.
        """

        print(self.ping_message)        
        self.fw.write_in_file(f'final/{self.target}.txt', 
                                self.ping_message)
        return self.dict_ping_info

    def  subnet_parse(self):
        """
        Func for parse result of subnet discover nmapModule analysis
        Output can be scaled with host dict. Map of this dict is:
        {host_1: {scan result of host_1}, host_2: {scan result of host_2} ... }
        Contain limit of printed ping report of concole (not on file)
        """
        tree = self.dict_trees['subnet']
        root = tree.getroot()
        limit=int(os.environ.get('MAX_PING'))
        file_limit=int(os.environ.get('MAX_PING_FILE'))
        self.subnet_host_dict = {}
        runstat = list(root)[-1]
        subnet_label = """
        ------------SUBNET DISCOVER VIA NMAP MODULE------------
        """
        n=0
        print(subnet_label)
        self.fw.write_in_file(f'final/{self.target}.txt', 
                                subnet_label)
        
        for i in list(root):
            if i.tag == 'host':
                tmp_host = {
                    'start': datetime.utcfromtimestamp(int(i.attrib['starttime']))
                                    .strftime("%y-%m-%d %H:%M:%S"),
                    'unix start timestamp':i.attrib['starttime'],
                    'state': list(i)[0].attrib['state'], 
                    'hostname': list(list(i)[2])[0].attrib['name'], 
                    'end': datetime.utcfromtimestamp(int(i.attrib['endtime'])).
                            strftime("%y-%m-%d %H:%M:%S"),
                    'unix end timestamp': i.attrib['endtime'],
                    'elapsed': list(runstat)[0].attrib['elapsed'],
                    'total host': list(runstat)[1].attrib['up']
                }

                self.subnet_host_dict.update({f'host_{n}': tmp_host})
                n += 1
                message =f"""
            ------------PING REPORT (SUBNET)------------
                START TIME: {tmp_host['start']}
                STATE: {tmp_host['state']}
                HOSTNAME: {tmp_host['hostname']}
                END TIME: {tmp_host['end']}
                ELAPSED: {tmp_host['elapsed']} s.
                № HOST: {n}/{tmp_host['total host']}
                
                """
                if n <= limit:
                    print(message)
                    self.fw.write_in_file(f'final/{self.target}.txt', message=message)
                elif n == limit+1:
                    print(f"{self.fw.WARNING}For buffer overflow reason script didn't print more then {limit} ping report in a row. "
                          f"If you didn't agree with this decision you can fix it with .env file in MAX_PING variable{self.fw.ENDC}")
                    self.fw.write_in_file(f'final/{self.target}.txt', message=message)
                elif n == file_limit+1:
                    print(f"{self.fw.WARNING}For create a readable file script didn't write in final file more then {file_limit} ping report in a row. "
                          f"If you didn't agree with this decision you can fix it with .env file in MAX_PING_FILE variable{self.fw.ENDC}")
        end_message = '------------END OF SUBNET DISCOVER------------'
        print(end_message)
        self.fw.write_in_file(f'final/{self.target}.txt', end_message)
        return self.subnet_host_dict
                          
                
    def whois_parse(self):
        """
        Func for parse result of whois nmapModule analysis
        """

    def traceroute_parse(self):
        """
        Func for parse result of traceroute nmapModule analysis
        """
        
    def geo_parse(self):
        """
        Func for parse result of traceroute nmapModule analysis
        """


    def finalize(self, save=True):
        """
        Main function of XML_parse class. Provide needed stage of class and 
        finalise XML parsing stage with one union conclusion about host activity.
        """

        greating = f'Library for VPN check in ip address\n'\
                    f'Init func contain host: {self.target}\n\n'

        label = (r'''
     _   _ __  __          _____   __      _______  _   _    _____ _    _ ______ _____ _  ________ _____  
    | \ | |  \/  |   /\   |  __ \  \ \    / /  __ \| \ | |  / ____| |  | |  ____/ ____| |/ /  ____|  __ \ 
    |  \| | \  / |  /  \  | |__) |  \ \  / /| |__) |  \| | | |    | |__| | |__ | |    | ' /| |__  | |__) |
    | . ` | |\/| | / /\ \ |  ___/    \ \/ / |  ___/| . ` | | |    |  __  |  __|| |    |  < |  __| |  _  / 
    | |\  | |  | |/ ____ \| |         \  /  | |    | |\  | | |____| |  | | |___| |____| . \| |____| | \ \ 
    |_| \_|_|  |_/_/    \_\_|          \/   |_|    |_| \_|  \_____|_|  |_|______\_____|_|\_\______|_|  \_\
                                                                                                       
                                                                                                       ''')


        print(greating, label)
        self.fw.write_in_file(f'final/{self.target}.txt',
                                greating)
        self.fw.write_in_file(f'final/{self.target}.txt',
                                label)
        for i in self.dict_trees.keys():
            if i == 'ping':
                ping_result = self.ping_parse()
            if i == 'subnet':
                subnet_result = self.subnet_parse()
            