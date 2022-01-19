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
    nmapWizard(target=target, auto=True)


if __name__ == '__main__':
    main('85.151.156.12')
