from cProfile import label
import warnings
import xml.etree.ElementTree as ET
import os

from datetime import datetime
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

        for i in lst_files:
            if i.find(target) != -1:
                lst_target_files.append(i)
        
        for i in lst_target_files:
            self.dict_trees.update({i.split('_')[-1].split('.')[0]:
                                        ET.parse(self.fw.tmp_storage / Path(i))})
        
        print('Found next methods' + '\n'.join(self.dict_trees.keys()))
        self.finalise()

    def ping_parse(self):
        """
        Func for pars XML tree of "ping" file

        Args:

            values_of_interetst (type: arr): arr with attributes in XML doc which 
                        can be interesting for potntial user
        """
        tree = self.dict_trees['ping']
        root  = tree.getroot()
        host = list(root)[2]
        runstats = list(root)[-1]
        self.dict_ping_info = {
            'start_time': root.items()[root.keys().index('start')][-1], \
            'state': list(host)[0].attrib['state'], \
            'hostname': list(list(host)[2])[0].attrib['name'], \
            'srtt': list(host)[3].attrib['srtt'], \
            'rttvar': list(host)[3].attrib['rttvar']
        }
        
        # For preety time format
        time = datetime.utcfromtimestamp(int(self.dict_ping_info  
                    ['start_time'])).strftime("%y-%m-%d %H:%M:%S")
        self.dict_ping_info.update({'preety_time': time})
        
        self.ping_message = f"""
        ------------PING REPORT------------\n
        START_AT: {self.dict_ping_info['preety_time']}\n
        HOST STATE: {self.dict_ping_info['state']}\n
        HOSTNAME: {self.dict_ping_info['hostname']}\n
        SMOOTHED I/O TIME: {self.dict_ping_info['srtt']}\n
        VARIANCE OF TRIP: {self.dict_ping_info['rttvar']}
        """

        print(self.ping_message)        
        self.fw.write_in_file(f'FINAL_RESULTS/{self.target}.txt', 
                                self.ping_message)

    def  subnet_parse(self):
        """
        Func for parse result of subnet discover nmapModule analysis
        """

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


    def finalise(self, save=True):
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
                ping_result = self.ping_pars()
            if i == 'subnet':

        