from nmap_module import nmapModule
from file_task import FileWork
from nmap_wizard import nmapWizard


def main(target, methods=None):
    """
    Main point to start VPN checker
    :param target: IP of target
    :return: VPN or not
    """
    vpn_check = False
    nmap = nmapModule(target)
    print(nmap.whois_ip_nmap())
    print(nmap.traceroute_with_geo())
    print(nmap.windows_default_scan())
    print(nmap.retrieving_geo())
    #nmapWizard(target=target, auto=True)


if __name__ == '__main__':
    main('8.8.8.8')
