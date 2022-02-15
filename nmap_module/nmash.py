import shlex
import subprocess as sp
import os
import termios
import sys
from SQLFunc.clickhouse import ClickHouse
from dotenv import load_dotenv

class Nmash:
    def __init__(self, target=None):
        load_dotenv()
        if os.name != 'posix':
            raise OSError('Sorry, but this module active only to \
                            UNIX users. For other OS, please, use other nmap modules')
        
        if target is None:
            print ('Class nmash did not have target! \
                                    Keep in mind to load this parameter before starting analysis')
        else:
            self.target = target
    
    def open_process(self, command, stdin=True,
                    stdout=True, stderr=True):
        """
        Func for create new process via fork 
        from original process

        Args:
        command (type: str): command to for new process
        stdin (type: bool): create sp.PIPE to stdin or not
        stdout (type: bool): create sp.PIPE to stdout or not 
        stderr (type: bool): create sp.PIPE to stderr or not
        """
        args = shlex.split(command)
        p = sp.Popen(args=args, stdin=sp.PIPE, stdout=sp.PIPE,\
                        stderr=sp.PIPE, shell=True)
        


    def ping(self):
        """
        Func for check status of host (up or down).
        """
        self.target
        


