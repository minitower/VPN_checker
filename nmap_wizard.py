from nmap_module import nmapModule
from file_task import FileWork
import os


class nmapWizard(nmapModule):

    def __init__(self, target=None, auto=False):
        """
        Addictive module for nmap module to get pretty result
        and push user to right side of module
        :param auto: if auto mode - just output result of checking
        target ip address
        """
        super().__init__()
        self.result_strong = None
        self.program = None
        self.state = None
        self.port = None
        self.save_path = self.fw.final_results
        self.target = target
        self.fw = FileWork()
        self.vpn_check = False
        self.methods = 'result_regular'
        if auto and target:
            if self.db_search_IP(target):
                print('Found free vpn service!')
                self.vpn_check = True
                self.fw.write_in_file(self.fw.final_results + f'{self.fw.cs}{self.target}.txt',
                                      message=f'Target: {target} was found in free VPN DB')
            print(self.windows_default_scan(self.target, methods=self.methods))
            self.after_regular_check()
            self.pars_result(self.target)
            self.result()

    def after_regular_check(self):
        """
        Func for build strong check, if needed
        :return: check result or False
        """
        methods = [i for i in os.walk('./results')][0][1]
        data = self.fw.read_from_file(self.fw.results + '\\result_regular\\' + self.target + '.txt')
        if data.find(', try -Pn') != -1:
            self.result_strong = self.strong_check(self.target)
            return self.result_strong
        else:
            return False

    def pars_result(self, target):
        if self.strong_check_complete:
            arr_data = self.result_strong.split('\n')
        else:
            arr_data = self.output.split('\n')
        header_index = arr_data.index('') + 1
        row = ' '
        n = 1
        while row != '':
            row = arr_data[header_index + n]
            if len(row.split(' ')) == 3:
                self.port = row.split(' ')[0].split('/')[0]
                self.state = row.split(' ')[1]
                self.program = row.split(' ')[-1]
                print(f'PORT {self.port} is {self.state}')
                if self.state == 'open':
                    if int(self.port) in self.default_ports:
                        self.vpn_check = True
                    else:
                        self.ports_checker.append(self.scoring_dict['open_port'])
                elif self.state == 'filtered':
                    if int(self.port) in self.default_ports:
                        self.vpn_check = True
                    else:
                        self.ports_checker.append(self.scoring_dict['filtered_port'])
            else:
                pass
            n += 1

    def result(self):
        if sum(self.ports_checker) >= 6 and not self.vpn_check:
            self.vpn_check = True
        print('ANALYSE RESULT: ')
        if self.vpn_check:
            print('IP address, probably, is VPN')
        else:
            print('IP address, probably, not VPN')
        return self.vpn_check
