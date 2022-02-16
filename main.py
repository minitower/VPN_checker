import pandas as pd

from vpn_check.nmap_module import nmapModule
from extra.file_task import FileWork
from SQLFunc.load_target_ip import *
from multiprocessing import Pool

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
   #target_df = target_df.loc[target_df['IP'].str.len() <= 16] # temporatly work for IPv4 only
    df = pd.read_csv('./Data_storage/IP_2022.01.01-2022.02.14.csv')
    df = df.set_index('click_id')
    
    #print(df['IP'].iloc[0])
    nmap = nmapModule(df['IP'].iloc[0])
    nmap.retrieving_geo()
    nmap.db_search_IP()
    nmap.traceroute_with_geo()
    nmap.whois_ip_nmap()
    nmap.full_info()


if __name__ == '__main__':
    main()