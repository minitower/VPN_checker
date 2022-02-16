import socket

from nmap_module import nmapModule
from extra.file_task import FileWork
import os


class nmapWizard(nmapModule):

    def __init__(self, target=None, strength=None, auto=False):
        """
        Addictive module for nmap module to get pretty result
        and push user to right side of module
        
        Args:
            target (type: str): IP address of host to analyse
            
            strength (type: int): mode scan agressive and quality (1 - fast (default), 2 - medium, 3 - slow)

            auto (type: bool): if True - script make choise without man over the screen
        """
        super().__init__(target)
        self.strength = strength
        self.auto = auto
        if self.strength == 1:
            methods


