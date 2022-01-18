from nmap_module import nmapModule
from file_task import FileWork
import os


class nmapWizard(nmapModule):

    def __init__(self, auto=False):
        """
        Addictive module for nmap module to get pretty result
        and push user to right side of module
        :param auto: if auto mode - just output result of checking
        target ip address
        """
        super().__init__()
        self.save_path = self.fw.final_results

    def after_regular_check(self, target):
        """
        Func for build strong check, if needed
        :param target: IP address of target
        :return: check result or False
        """
        methods = [i for i in os.walk('./results')][0][1]
        data = self.fw.read_from_file(self.fw.results + '\\result_regular\\' + target + '.txt')
        if data.find(', try -Pn'):
            return self.strong_check(target)
        else:
            return False

