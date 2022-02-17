from cgitb import strong
import xml.etree.ElementTree as ET
import os
from datetime import datetime
from extra.file_task import FileWork
from pathlib import Path


class XML_parse:
    
    def __init__(self, target, methods:list=['all']):
        """
        Class for pars XML from nmap_module output.
        Class automatate upload all trees, which available in Tmp_storage

        Args:
            target (type: str): IP address of host with files in Tmp_storage
            methods (type: str): methods from nmapModule to use
        """
        self.fw = FileWork()
        self.target = target
        lst_target_files = []
        lst_files = [i for i in os.walk(self.fw.tmp_storage)][-1][-1]
        self.dict_trees = {}
        self.all_methods = ['ping', 'ports', 'geo', 'traceroute', 'subnet', 'full']
        lst_filtered = []
        
        if 'all' in methods:
            methods = self.all_methods
        
        for i in lst_files:
            method = i.split('_')[-1].split('.')[0]
            if method in methods:
                lst_filtered.append(i)
        
        with open(f'final/{self.target}.txt', 'w') as f: # to be sure: file will be empty
            pass

        for i in lst_filtered:
            if i.find(target) != -1:
                lst_target_files.append(i)
        
        for i in lst_target_files:
            self.dict_trees.update({i.split('_')[-1].split('.')[0]:
                                        ET.parse(self.fw.tmp_storage / Path(i))})
        
        #print('Found next methods:\n' + '\n'.join(self.dict_trees.keys()))

    def ping_parse(self):
        """
        Func for pars XML tree of "ping" file
        """
        tree = self.dict_trees['ping']
        root  = tree.getroot()
        host = list(root)[2]
        runstats = list(root)[-1]
        
        if len(list(root)) >=4:
            self.dict_ping_info = {
                'start time': root.items()[root.keys().index('start')][-1], 
                'state': list(host)[0].attrib['state'], 
                'end time': list(runstats)[0].attrib['time'],
                'elapsed': list(runstats)[0].attrib['elapsed']
            }
            
            try:
                self.dict_ping_info.update({'hostname': list(list(host)[2])[0].attrib['name']})
            except KeyError:
                self.dict_ping_info.update({'hostname': 'not found'})
            except IndexError:
                self.dict_ping_info.update({'hostname': 'not found'})
            try:
                self.dict_ping_info.update({'srtt': list(host)[3].attrib['srtt']})
            except KeyError:
                self.dict_ping_info.update({'srtt': "can't calculate"})
            except IndexError:
                self.dict_ping_info.update({'srtt': "can't calculate"})
            try:
                self.dict_ping_info.update({'rttvar': list(host)[3].attrib['rttvar']})
            except KeyError:
                self.dict_ping_info.update({'rttvar': "can't calculate"})
            except IndexError:
                self.dict_ping_info.update({'rttvar': "can't calculate"})
            # For pretty time format
            time = datetime.utcfromtimestamp(int(self.dict_ping_info  
                        ['start time'])).strftime("%y-%m-%d %H:%M:%S")
            self.dict_ping_info.update({'pretty_start_time': time})
            time = datetime.utcfromtimestamp(int(self.dict_ping_info
                        ['end time'])).strftime("%y-%m-%d %H:%M:%S")
            self.dict_ping_info.update({'pretty_end_time': time})

            message = f"""
            ------------PING REPORT------------
            START AT: {self.dict_ping_info['pretty_start_time']}
            HOST STATE: {self.dict_ping_info['state']}
            HOSTNAME: {self.dict_ping_info['hostname']}
            SMOOTHED I/O TIME: {self.dict_ping_info['srtt']}
            VARIANCE OF TRIP: {self.dict_ping_info['rttvar']}
            END AT: {self.dict_ping_info['pretty_end_time']}
            ELAPSED: {self.dict_ping_info['elapsed']} s.
            """
            print(message)
        
        elif len(list(root)) == 3:
            self.dict_ping_info = {
                'state': 'down',
                'start time': list(list(root)[2])[0].attrib['time'],
                'elapsed': list(list(root)[2])[0].attrib['elapsed']
            }
            time = datetime.utcfromtimestamp(int(self.dict_ping_info  
                        ['start time'])).strftime("%y-%m-%d %H:%M:%S")
            self.dict_ping_info.update({'pretty_start_time': time})
            
            message = f"""
            ------------PING REPORT------------
            START AT: {self.dict_ping_info['pretty_start_time']}
            STATE: {self.dict_ping_info['state']}
            ELAPSED: {self.dict_ping_info['elapsed']}
            """
            print(message)
        self.dict_ping_info.update({'message': message})
        return self.dict_ping_info

    def  subnet_parse(self):
        """
        Func for parse result of subnet discover nmapModule analysis
        Output can be scaled with host dict. Map of this dict is:
        {host_1: {scan result of host_1}, host_2: {scan result of host_2} ... }
        Contain limit of printed ping report of concole (not on file)
        """
        tree = self.dict_trees['subnet']
        root = tree.getroot()
        limit=int(os.environ.get('MAX_PING'))
        file_limit=int(os.environ.get('MAX_PING_FILE'))
        self.subnet_host_dict = {}
        runstat = list(root)[-1]
        subnet_label = """
        ------------SUBNET DISCOVER VIA NMAP MODULE------------
        """
        n=0
        print(subnet_label)
        
        for i in list(root):
            if i.tag == 'host':
                tmp_host = {
                    'start': datetime.utcfromtimestamp(int(i.attrib['starttime']))
                                    .strftime("%y-%m-%d %H:%M:%S"),
                    'unix start timestamp':i.attrib['starttime'],
                    'state': list(i)[0].attrib['state'], 
                    'hostname': list(list(i)[2])[0].attrib['name'], 
                    'end': datetime.utcfromtimestamp(int(i.attrib['endtime'])).
                            strftime("%y-%m-%d %H:%M:%S"),
                    'unix end timestamp': i.attrib['endtime'],
                    'elapsed': list(runstat)[0].attrib['elapsed'],
                    'total host': list(runstat)[1].attrib['up']
                }

                self.subnet_host_dict.update({f'host_{n}': tmp_host})
                n += 1
                message =f"""
            ------------PING REPORT (SUBNET)------------
                START TIME: {tmp_host['start']}
                STATE: {tmp_host['state']}
                HOSTNAME: {tmp_host['hostname']}
                END TIME: {tmp_host['end']}
                ELAPSED: {tmp_host['elapsed']} s.
                № HOST: {n}/{tmp_host['total host']}
                
                """
                if n <= limit:
                    print(message)
                    fmessage += message
                elif n == limit+1:
                    print(f"{self.fw.WARNING}For buffer overflow reason script didn't print more then {limit} ping report in a row. "
                          f"If you didn't agree with this decision you can fix it with .env file in MAX_PING variable{self.fw.ENDC}")
                    fmessage += message
                elif n == file_limit+1:
                    print(f"{self.fw.WARNING}For create a readable file script didn't write in final file more then {file_limit} ping report in a row. "
                          f"If you didn't agree with this decision you can fix it with .env file in MAX_PING_FILE variable{self.fw.ENDC}")
        end_message = '\t------------END OF SUBNET DISCOVER------------\n\n'
        print(end_message)
        self.subnet_host_dict.update({'message': subnet_label + fmessage + end_message})
        
        return self.subnet_host_dict
                          
    def traceroute_parse(self):
        """
        Func for parse result of traceroute nmapModule analysis
        """
        tree = self.dict_trees['traceroute']
        root = tree.getroot()
        hop_key_arr = []
        trace_str = ''
        self.dict_traceroute = {
            'state': list(list(root)[3])[0].attrib['state'],
            'hostname': list(list(list(root)[4])[2])[0].attrib['name'], 
            'elapsed': list(list(root)[5])[0].attrib['elapsed']
        }
        
        for i in list(list(list(root)[4])[4])[:]:
            if 'host' in i.keys() :
                self.dict_traceroute.update({'hop_'+i.attrib['ttl']: \
                    '\n\t' + 'IP: ' + i.attrib['ipaddr'] + '\t' + \
                               'RTT: ' + i.attrib['rtt'] +  '\t' + \
                               'HOST: ' + i.attrib['host']})
            else:
                    self.dict_traceroute.update({'hop_'+i.attrib['ttl']: \
                    '\n\t' + 'IP: ' + i.attrib['ipaddr'] + '\t' + \
                               'RTT: ' + i.attrib['rtt'] +  '\t' + \
                               'HOST: not found on home DNS network'})
            
            
            hop_key_arr.append('hop_'+i.attrib['ttl'])
        
        for i in hop_key_arr:
            trace_str += self.dict_traceroute[i]

        message = f'''
        ------------TRACEROOT REPORT------------
        STATE: {self.dict_traceroute['state']}
        HOSTNAME: {self.dict_traceroute['hostname']}
        TRACE:{trace_str}
        ELAPSED: {self.dict_traceroute['elapsed']}
        '''
        
        print(message)
        self.dict_traceroute.update({'message': message})
        return self.dict_traceroute
                    
    def port_parse(self):
        """
        Func for parse result of nmapModule port scan
        """
        tree = self.dict_trees['ports']
        root = tree.getroot()
        port_arr = []
        port_str = ''
        lst_port = []
        lst_state = []
        lst_service = []    
        self.port_dict = {
            'state': list(list(root)[3])[0].attrib['state'],
            'elapsed': list(list(root)[-1])[0].attrib['elapsed']
        }
        n=0
        for i in list(list(list(root)[3])[3])[:]:
            port_info = (i.attrib['protocol'],
                             i.attrib['portid'], 
                             list(i)[0].attrib['state'],
                             list(i)[1].attrib['name'])
            port_arr.append(port_info)
            self.port_dict.update({f'port_{n}': port_info})
            n+=1
        for i in port_arr:
            port_str += f'''
            PORT: {i[0]}/{i[1]} \tSTATE: {i[2]} \tSERVICE: {i[3]}\n
            '''            
        
        message = f'''
        ------------PORT REPORT------------
        STATE: {self.port_dict['state']}
        OPEN PORTS:
            {port_str}
        ELAPSED: {self.port_dict['elapsed']}
        '''
        print(message)
        self.port_dict.update({'message': message})
        return self.port_dict
        
    def geo_parse(self):
        """
        Func for parse result of traceroute nmapModule analysis
        """
        tree = self.dict_trees['geo']
        root = tree.getroot()
        attr_arr = []
        self.geo_dict = {
            'start time': list(root)[3].attrib['starttime'],
            'state': list(list(root)[3])[0].attrib['state'],
            'end time': list(root)[3].attrib['endtime'],
            'elapsed': list(list(root)[4])[0].attrib['elapsed'],
        }
        
        for i in list(list(list(list(root)[3])[4])[0]):
            self.geo_dict.update({i.attrib['key']: i.text})
            attr_arr.append(i.attrib['key'])
        
        # For pretty time format
        time = datetime.utcfromtimestamp(int(self.geo_dict  
                    ['start time'])).strftime("%y-%m-%d %H:%M:%S")
        self.geo_dict.update({'pretty start time': time})
        
        time = datetime.utcfromtimestamp(int(self.geo_dict
                    ['end time'])).strftime("%y-%m-%d %H:%M:%S")
        self.geo_dict.update({'pretty end time': time})
        
        message = f"""
        ------------GEO PLUGIN (NSE)------------
        START AT: {self.geo_dict['pretty start time']}
        STATE: {self.geo_dict['state']}
        LATITUDE: {self.geo_dict['latitude']}
        LONGITUDE: {self.geo_dict['longitude']}
        CITY: {self.geo_dict['city']}
        REGION: {self.geo_dict['region']}
        COUNTRY: {self.geo_dict['country']}
        END AT: {self.geo_dict['pretty end time']}
        ELAPSED: {self.geo_dict['elapsed']}
        -------------END GEO PLUGIN-------------
        """
        print(message)
        self.geo_dict.update({'message': message})
        return self.geo_dict
             
    def full_parse(self):
        """
        Func for parse result of full host info nmapModule analyse
        """
        tree = self.dict_trees['full']
        root = tree.getroot()
        arr_existed_ports = []
        self.dict_full = {
            'state': list(list(root)[4])[0].attrib['state'],
            'hostname': list(list(list(root)[4])[2])[0].attrib['name'],
            'n_closed': list(list(list(root)[4])[3])[0].attrib['count'],
            'os name':  list(list(list(root)[4])[4])[1].attrib['name'],
            'os info accuracy': list(list(list(root)[4])[4])[1].attrib['accuracy'],
            'os type': list(list(list(list(root)[4])[4])[1])[0].attrib['type'],
            'os vendor': list(list(list(list(root)[4])[4])[1])[0].attrib['vendor'],
            'os family': list(list(list(list(root)[4])[4])[1])[0].attrib['osfamily'],
            'os generation': list(list(list(list(root)[4])[4])[1])[0].attrib['osgen'], 
            'uptime': list(list(root)[4])[5].attrib['seconds'], 
            'lastboot': list(list(root)[4])[5].attrib['lastboot'],
            'distance': list(list(root)[4])[6].attrib['value'],
            'srtt': list(list(root)[4])[11].attrib['srtt'],
            'rttvar': list(list(root)[4])[11].attrib['rttvar'],
            'to': list(list(root)[4])[11].attrib['to'],
            'elapsed': list(list(root)[5])[0].attrib['elapsed'],
        }
        for i in list(list(list(root)[4])[3])[1:]:
            arr_existed_ports.append((list(list(list(root)[4])
                                        [3])[1].attrib['portid'],
                                   list(list(list(list(root)[4])[3])
                                        [1])[0].attrib['state'],
                                   list(list(list(list(root)[4])[3])
                                        [1])[1].attrib['name']))
        str_open_ports = ''
        for i in arr_existed_ports:
            str_open_ports += f'''
            PORT: {i[0]}\tSTATE: {i[1]}\tSERVICE: {i[2]}\n    
            '''
        
        
        message = f"""
        ------------FULL HOST REPORT------------
        STATE: {self.dict_full['state']}
        HOSTNAME: {self.dict_full['hostname']}
        № CLOSED PORTS: {self.dict_full['n_closed']}
        OPEN PORTS: 
            {str_open_ports}
        OS NAME: {self.dict_full['os name']}
        OS INFO ACCURACY: {self.dict_full['os info accuracy']}
        OS TYPE: {self.dict_full['os type']}
        OS VENDOR: {self.dict_full['os vendor']}
        OS FAMILY: {self.dict_full['os family']}
        OS GENERATION: {self.dict_full['os generation']}
        UPTIME: {self.dict_full['uptime']}
        LASTBOOT: {self.dict_full['lastboot']}
        DISTANCE: {self.dict_full['distance']}
        SRTT: {self.dict_full['srtt']}
        RTTVAR: {self.dict_full['rttvar']}
        TO: {self.dict_full['to']}
        ELAPSED: {self.dict_full['elapsed']}
        ------------END FULL REPORT------------
        """
        print(message)
        self.dict_full.update({'message': message})
        return self.dict_full

    def finalize(self, label=True):
        """
        Main function of XML_parse class. Provide needed stage of class and 
        finalise XML parsing stage with one union conclusion about host activity.
        
        Args:
            label (type: bool): if True - print script label on start of script
        """
        self.parse_result = {}
        for i in self.dict_trees.keys():
            if i == 'ping':
                ping_result = self.ping_parse()
                self.parse_result.update({'ping': ping_result})
            if i == 'subnet':
                subnet_result = self.subnet_parse()
                self.parse_result.update({'subnet': subnet_result})
            if i == 'geo':
                geo_result = self.geo_parse()
                self.parse_result.update({'geo': geo_result})
            if i == 'full':
                full_result = self.full_parse()
                self.parse_result.update({'full': full_result})
            if i == 'traceroute':
                trace_result = self.traceroute_parse()
                self.parse_result.update({'trace': trace_result})
            if i == 'ports':
                port_result = self.port_parse()
                self.parse_result.update({'ports': port_result})
        if len(self.parse_result) == 1:
            self.parse_result = self.parse_result\
                                    [list(self.dict_trees.keys())[0]]
        return self.parse_result
        