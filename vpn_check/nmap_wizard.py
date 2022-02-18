import sys
from urllib import response

from numpy import true_divide
sys.path.append('/home/minitower/projects/VPN_checker')
from vpn_check.nmap_module import nmapModule
from extra.file_task import FileWork
from extra.xml_parse import XML_parse
import os


class nmapWizard(nmapModule):

    def __init__(self, target=None, strength=None, auto=False, print = True, expected_location=None):
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
        self.fw = FileWork()
        self.greating_screen()
        self.expected_location = expected_location
        self.auto = auto
        self.vpn_prob = 0
        if self.expected_location is None:
            self.expected_location = os.environ.get('LOCATION')
        if self.expected_location is None:
            self.expected_location = 'Russia'
            
        
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
        
    def hostname_analyse(self, name):
        """
        Func for build conclusion about hostname
        """
        lst_names = ['vpn', 'vpngate', 'open', 'free', 'proton']
        for i in lst_names:
            if i in name:
                print(f'{self.fw.WARNING}STRANGE HOSTNAME{self.fw.ENDC}')
                if not self.auto:
                    ask = input('You think, i am right? (Y/n)> ')
                    if ask.lower() in ['y', '', 'yes']:
                        print(f'{self.fw.WARNING}VPN FOUND: {self.target}{self.fw.ENDC}')
                        return 'VPN'
                    else:
                        print(f'{self.fw.WARNING}KEEP RESEARCHING{self.fw.ENDC}')
                        return 'USER'
                else:
                    print(f'{self.fw.WARNING}VPN FOUND: {self.target}{self.fw.ENDC}')
                    return 'VPN'
                
    def port_result_analyse(self, xml_result):
        """
        Func for analyse result in XML parsing function
        
        Args:
            xml_result (type: dict): output of XML_parse class
        """
        message = f"""3) Port research give next answers:\n"""
        for i in xml_result.keys():
            if i.find('port') != -1:
                n = i.split('_')[-1]
                state = xml_result[i][0]
                port_id = xml_result[i][1]
                common = self.sql.execute(f'SELECT common FROM vpn_port where port == {port_id};').fetchall()[0][0]
                if common.upper == 'FALSE':
                    common = False
                else:
                    common = True
                service = xml_result[i][2]
                if state == 'filtered' and common:
                    self.vpn_prob += 0
                    red = 'USER' if common else 'VPN'
                    message += f"""3.{n}) Port {port_id} is not unique for VPN services (this is a {service}) and 
                    firewall try to block them. Probably, this is a home network"""
                if state == 'open' and common:
                    self.vpn_prob += 3
                    message += f"""3.{n}) Port {port_id} is not unique for VPN services (this is a {service}), but 
                    this port is open from outside. This state can be signal that the host is a server (but not only VPN).
                    But, this still can be home network with inattentive owner"""
                if state == 'filtered' and not common:
                    self.vpn_prob += 7
                    message += f"""3.{n}) Port {port_id} is common for VPN services (this is a {service}), but 
                    this port filtered by firewall. This state of port almost always talk about VPN service"""
                if state == 'open' and not common:
                    self.vpn_prob += 10
                    message += f"""3.{n}) Port {port_id} is common for VPN services (this is a {service}) and port open to
                    Internet connection. That state tells about free VPN services with no system administrative (very creepy for
                    users). But, this, of course, can be interpreted as VPN evidence"""    
        return message                
                           
    def start(self):
        """
        Main func - run and coordinate process of nmapModule
        """
        # Firstly, ping host to get information about state
        self.ping()
        ping_request = XML_parse(self.target, methods=['ping'])
        ping_response = ping_request.finalize()
        self.conclusion = f'''
        VPN_checker automate scan. Subclass of nmapModule on Nmap VPN checker
        
        SETTINGS: 
            TARGET IP: {self.target}
            STRENGTH OF SCAN: {self.strength}
            AUTO-MOD: ON
        
        CONCLUSION:
        
            '''
        if ping_response['state'] == 'up':
            print(f'{self.fw.WARNING}HOST UP, CONTINUE{self.fw.ENDC}')
            geo_scan = True
            self.conclusion += '1) Host is up on link and ping has reach target. So, continue'
        else:
            print(f'{self.fw.WARNING}HOST DOWN, STOP{self.fw.ENDC}')
            self.conclusion += '1) Host seams to be down. So, this host can be unreachable VPN server, but most probably' + \
                'this is individual machine (and now this machine is off)'
            return 'USER'
        
        if ping_response['hostname'] != 'not found':
            print(f'{self.fw.WARNING}HOST HAVE HOSTNAME IN OPEN DNS. '+ \
                        F'BUT MAYBE THIS FOR PRIVATE LOCAL NET.{self.fw.ENDC}')
        
            hostname_check = self.hostname_analyse(ping_response['hostname'])
            if hostname_check == 'VPN':
                return 'VPN'
        
        # If host up - try to get geolocation of host.
        self.retrieving_geo()
        geo_request = XML_parse(self.target, methods=['geo'])
        geo_response = geo_request.finalize()
        if geo_response['country'] != 'Russia':
            print(f'{self.fw.WARNING}HOST LOCATE DID NOT COMPARE WITH '+ \
                        f'EXPECTED LOCATION{self.fw.ENDC}')
            self.vpn_prob += 5
        else:
            print(f'{self.fw.WARNING}HOST HAVE RUSSIAN IP ADDRESS{self.fw.ENDC}')
        
        self.port_analyse()
        port_request = XML_parse(self.target, methods=['ports'])
        port_response = port_request.finalize()
        self.conclusion = self.port_result_analyse(port_response)
        if self.vpn_prob >= 10:
            print(f'{self.fw.WARNING}HOST, PROBABLY, VPN{self.fw.ENDC}')
            return 'VPN'
        elif self.vpn_prob >= 5 and self.vpn_prob < 10:
            print (f'{self.fw.WARNING}NOT SURE, KEEP RESEARCH{self.fw.ENDC}')
        elif self.vpn_prob < 5:
            print (f'{self.fw.WARNING}HOST, PROBABLY, NOT VPN{self.fw.ENDC}')
            return 'USER'
        
