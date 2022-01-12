import os
import pandas as pd
import socket

import requests

from clickhouse import ClickHouse

sql = ClickHouse(os.getenv('HOST'),
                 os.getenv('LOGIN'),
                 os.getenv('PASSWORD'))

df = pd.DataFrame(sql.execute("""SELECT ip, user_id, device_type_id, country_code, created_at
FROM ads.user_registration_data
where created_at >= CAST('2022-01-12 00:00:00' as DateTime)"""))

url = "https://iplegit.p.rapidapi.com/full"

query = {"ip":df[0].values[0]}

headers = {
    'x-rapidapi-host': "iplegit.p.rapidapi.com",
    'x-rapidapi-key': "dbf7c677dfmsh8ec60f0e90d5f55p1c8982jsn2613dbcf02fb"
    }

response = requests.request("GET", url, headers=headers, params=query)

print(response.text)


