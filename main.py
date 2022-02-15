import pandas as pd

from vpn_check.nmap_module import nmapModule
from extra.file_task import FileWork
from extra.ch_driver import ClickHouse
from multiprocessing import Pool

p_num = 5 # num of process

def load_target_ip(limit=None, df_return=True, date=None):
    """
    Func for create and execute query for "click_data" table
    with current IP address.
    :param df_return: if True func return pd.DataFrame object,
    else return a SQL response
    :param limit: int, limit of downloaded IP addresses
    :param referrer: arr, hostname of IP address
    :param date: date-like, date for limitation of fetched rows 
    :return: pd.DataFrame with IP addresses or SQL response
    """
    ch_sql = ClickHouse(env_login=True)
    if not date is None and limit is None:
        sql_response = ch_sql.execute(f"""SELECT click_id, ip 
                                            FROM online.click_data cd 
                                            WHERE click_id in (SELECT ld.click_id
							                                    FROM online.lead_data ld
							                                    WHERE toDate(ld.updated_at) >= '{str(date)}')""")
    elif not limit is None and date is None:
        sql_response = ch_sql.execute(f"""SELECT click_id, ip 
                                            FROM online.click_data cd 
                                            LIMIT {limit}""")
    elif not limit is None and not date is None:
        sql_response = ch_sql.execute(f"""SELECT click_id, ip 
                                            FROM online.click_data cd 
                                            WHERE click_id in (SELECT ld.click_id
							                                    FROM online.lead_data ld
							                                    WHERE toDate(ld.updated_at) >= {date} and
                                                                LIMIT {limit})""")
    else:
        db_warn = input(f"""
                        {fw.WARNING}Func didn't have LIMIT or 'date' column like limitation of response.
                        Therefore, this operation will be quite expensive for the database. 
                        Confirm execution?[y/N]{fw.ENDC}>  
                        """)
        if db_warn.lower() in ['yes', 'y']:
            sql_response = ch_sql.execute(f"""SELECT click_id, ip 
                                            FROM online.click_data cd""")
        else:
            raise KeyboardInterrupt('Operation cancel by user')
    if df_return:
        targets_ip = pd.DataFrame(sql_response, columns=['click_id', 'IP'])
    else:
        targets_ip = sql_response.copy()
    return targets_ip


def main(target, methods=None):
    """
    Func with build nmap module for one 
    target and create right way of analysis

    Args:
        target (string): IP addresses of target IP address
    """
    nmap = nmapModule(target)
    nmap.db_search_IP()
    print(f'{fw.BOLD}LOAD MAIN INFORMATION ABOUT IP ADDRESS{fw.ENDC}')
    print(f'{fw.BOLD}PATH OF LOG WITH INFO: {fw.tmp_storage}/{target}.txt{fw.ENDC}')
    print('\n'.join(nmap.whois_ip_nmap()))
    print('\n'.join(nmap.retrieving_geo()))
    print('\n'.join(nmap.traceroute_with_geo()))
    print(f'\n\n\n{fw.BOLD}ANALYSIS RESULT: {fw.ENDC}')
    print('\n'.join(nmap.windows_default_scan(methods=methods)))
    print('\n'.join(nmap.hostname_analyse()))


if __name__ == '__main__':
    
   # fw = FileWork()
   # target_df = load_target_ip(date=r'2022-01-01')
   # target_df = target_df.loc[target_df['IP'].str.len() <= 16] # temporatly work for IPv4 only
    df = pd.read_csv('./Data_storage/IP_2022.01.01-2022.02.14.csv')
    df.set_index('click_id')
    

    nmap = nmapModule(df['IP'].iloc[0])
    nmap.retrieving_geo()
    nmap.db_search_IP()
    nmap.traceroute_with_geo()
    nmap.whois_ip_nmap()
    nmap.full_info()
