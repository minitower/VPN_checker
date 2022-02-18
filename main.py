import pandas as pd
from extra.file_task import FileWork
from vpn_check.nmap_wizard import nmapWizard
import random

p_num = 5 # num of process

fw = FileWork()

def main():
    """
    Func with build nmap module for one 
    target and create right way of analysis

    Args:
    """
    fw = FileWork()
   #target_df = load_target_ip(date=r'2022-01-01')
   #target_df = target_df.loc[target_df['IP'].str.len() <= 16] # temporalty work for IPv4 only
    df = pd.read_csv('./Data_storage/IP_2022.01.01-2022.02.14.csv')
    target = df['IP'].iloc[random.randint(1, 100)]
    
    wiz = nmapWizard(target=target)
    wiz.start()


if __name__ == '__main__':
    main()