from nmap_module import nmapModule
from file_task import FileWork
from nmap_wizard import nmapWizard


def main(target, methods=None):
    """
    Main point to start VPN checker
    :param target: IP of taqrget
    :return: VPN or not
    """
    vpn_check = False
    nmap = nmapModule()
    nmap_wiz = nmapWizard()
    fw = FileWork()

    print(target)
    if nmap.db_search_IP(target):
        print('Found free vpn service!')
        vpn_check = True
        fw.write_in_file(fw.final_results + f'{fw.cs}{target}.txt',
                         message=f'Target: {target} was found in free VPN DB')
        return vpn_check
    print(nmap.windows_default_scan(target, methods=methods))
    print(nmap_wiz.after_regular_check(target))

    return vpn_check


if __name__ == '__main__':
    main('18.190.58.3')
