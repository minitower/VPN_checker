import pandas as pd 
from clickhouse import ClickHouse
from extra.file_task import FileWork

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
    fw = FileWork()
    ch_sql = ClickHouse()
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