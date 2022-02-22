import pandas as pd
from extra.file_task import FileWork
from vpn_check.nmap_wizard import nmapWizard
from dotenv import load_dotenv

p_num = 5 # num of process
fw = FileWork()    

if __name__ == '__main__':
    fw = FileWork()
    load_dotenv()
    #sql = ClickHouse()
    #target_df = load_target_ip(date=r'2022-02-01')
    #target_df = target_df.loc[target_df['IP'].str.len() <= 16] # temporalty work for IPv4 only
    df = pd.read_csv('./IP_Table.csv')
    target_df = df['ip'].values
    for i in target_df:
        nmapWizard(target=i)
        fw.trash_collector(i)
