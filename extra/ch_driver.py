import os

from clickhouse_driver import Client
import dotenv


class ClickHouse:

    def __init__(self, host=None, username=None, password=None, env_login=True):
        """
        Init of ClickHouse driver
        :param host:
        :param username:
        :param password:
        """
        if env_login:
            dotenv.load_dotenv()
            self.host = os.environ.get('HOST')
            self.username = os.environ.get('LOGIN')
            self.password = os.environ.get('PASSWORD')
        else:
            self.host = host
            self.username = username
            self.password = password
        self.client = Client(self.host,
                             user=self.username,
                             password=self.password)

    def execute(self, query):
        """
        Func for execute query
        :param query: string, executed query
        :return: sql data
        """
        return self.client.execute(query)


