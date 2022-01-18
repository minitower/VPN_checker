from nmap_module import nmapModule
from file_task import FileWork


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


