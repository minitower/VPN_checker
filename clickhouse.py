import os
from clickhouse_driver import Client
import requests


class ClickHouse:

    def __init__(self, host, username, password):
        """
        Init of ClickHouse driver
        :param host:
        :param username:
        :param password:
        """
        self.host = host
        self.username = username
        self.password = password
        self.client = Client(self.host,
                             user=username,
                             password=self.password)

    def execute(self, query):
        """
        Func for execute query
        :param query: string, executed query
        :return: sql data
        """
        return self.client.execute(query)
