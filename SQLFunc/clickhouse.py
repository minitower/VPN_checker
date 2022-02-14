import os
from clickhouse_driver import Client
from dotenv import load_dotenv

class ClickHouse:

    def init(self, host=None, username=None, password=None, env=True):
        """
        Init of ClickHouse driver
        :param host: ipv4 address, where DB dislocated
        :param username: username for DB access
        :param password: pass of current username
        :param env: bool, if True - load params from .env
        """
        self.host = host
        self.username = username
        self.password = password
        self.env_connect()
        self.client = Client(self.host,
                             user=self.username,
                             password=self.password)

    def env_connect(self):
        """
        Func for load data from env file and configure
        nercessury params if cannot find this param in 
        class
        :return: None
        """
        load_dotenv()
        if self.host is None:
            self.host = os.environ.get('HOST')
        if self.username is None:
            self.username = os.environ.get('LOGIN')
        if self.password is None:
            self.password = os.environ.get('PASSWORD')
        
        
    def load_sql_from_file(self, path):
        """
        Func for create python string object from 
        file (.sql or someone else)

        Args:
            path ('str'): path to file
        :return: str with sql query
        """
        with open(path, 'r') as f:
            sql_query = f.read()
        return sql_query

    def execute(self, query=None, path=None):
        """
        Func for execute query
        :param query: string, executed query
        :param path: str, path to file with executed str
        :return: sql data
        """
        if path:
            query = self.load_sql_from_file(path=path)
        data = self.client.execute(query)
        return data