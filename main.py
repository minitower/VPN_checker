import pandas as pd
from extra.file_task import FileWork
from vpn_check.nmap_wizard import nmapWizard
import random
from multiprocessing import Pool

p_num = 5 # num of process

fw = FileWork()    

if __name__ == '__main__':
    fw = FileWork()
   #target_df = load_target_ip(date=r'2022-01-01')
   #target_df = target_df.loc[target_df['IP'].str.len() <= 16] # temporalty work for IPv4 only
    df = pd.read_csv('./Data_storage/IP_2022.01.01-2022.02.14.csv')
    target_df = df['IP'].values
    
    for i in target_df:
        nmapWizard(target=i)
        fw.trash_collector(i)    
