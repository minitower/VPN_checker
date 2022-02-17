import sys
from urllib import response
sys.path.append('/home/minitower/projects/VPN_checker')
from vpn_check.nmap_module import nmapModule
from extra.file_task import FileWork
from extra.xml_parse import XML_parse
import os


class nmapWizard(nmapModule):

    def __init__(self, target=None, strength=None, auto=False, print = True):
        """
        Addictive module for nmap module to automatate script and 
        analyse result of report. Can make some decision to host accuracy and 
        find more info about it with nmapModule methods
        
        Args:
            target (type: str): IP address of host to analyse
            strength (type: int): mode scan agressive and quality (1 - fast (default), 2 - medium, 3 - slow)
            auto (type: bool): if True - script make choice without man over the screen
            print (type: bool): if True - print XML_parse module with print args for each nmapModule result
        """
        super().__init__(target)
        self.target = target
        self.strength = strength
        self.auto = auto
        self.fw = FileWork()
        self.greating_screen()
        
    def greating_screen(self):
        """
        Func for print label and write them on final file
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
        
    def start(self):
        """
        Main func - run and coordinate process of nmapModule
        """
        self.ping()
        ping_request = XML_parse(self.target, methods=['ping'])
        ping_response = ping_request.finalize()
        print(ping_response)
        if ping_response['state'] == 'down':
            print(f'{self.fw.WARNING} HOST DOWN, TRY FORCED SCAN{self.fw.ENDC}')
            self.strong_ping()
            sping_request = XML_parse(self.target, methods=['ping'])
            sping_response = sping_request.finalize()
            if sping_response['state'] == 'down':
                print(f'{self.fw.WARNING} HOST IS REALLY DOWN, END OF SCANING{self.fw.ENDC}')
                end_scan = True
            else:
                print(f'{self.fw.WARNING} HOST IS UP. TRY TO GET HIS GEOLOCATION{self.fw.ENDC}')
                geo_scan = True
        if geo_scan == True:
            self.retrieving_geo()
            geo_request = XML_parse(self.target, methods=['geo'])
            geo_response = geo_request.finalize()
wiz = nmapWizard('57.254.58.92')
wiz.start()
