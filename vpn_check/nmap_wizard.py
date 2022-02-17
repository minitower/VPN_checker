import socket
from unittest.mock import NonCallableMagicMock

from nmap_module import nmapModule
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
        
    def start(self):
        """
        Main func - run and coordinate process of nmapModule
        """
        self.ping()
        
        
