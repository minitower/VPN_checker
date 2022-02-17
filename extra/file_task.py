import json
import os
from pathlib import Path
import sys
import pandas as pd
from dotenv import load_dotenv


class FileWork:
    def __init__(self):
        # Check separation
        self.failed_source = []
        self.downloaded = []

        # Init path of project
        self.direction_path = Path(os.path.dirname(__file__))
        if not os.path.exists(self.direction_path / 'main.py'):
            self.direction_path = self.direction_path.parent
        
        # Check correctness of project file system
        if os.path.exists(self.direction_path / 'Data_storage') and   \
            os.path.exists(self.direction_path / 'Data_storage' / 'vpn.db'):
            self.path_with_data = self.direction_path / 'Data_storage'
            
        elif os.path.exists(self.direction_path / 'Data_storage') and not \
        os.path.exists(self.direction_path / 'Data_storage' / 'vpn.db'):
            raise FileNotFoundError("FATAL ERROR! \n Can't found 'vpn.db'. Please, check correctness of project File System!")
        
        elif not os.path.exists(self.direction_path / 'Data_storage'):
            raise FileNotFoundError("FATAL ERROR!\nCan't found 'Data_storage' in root of project file system.")
        
        if os.path.exists(self.direction_path / 'Tmp_storage'):
            self.tmp_storage = self.direction_path / 'Tmp_storage'
        else:
            os.mkdir(self.direction_path / 'Tmp_storage')
            self.tmp_storage = self.direction_path / 'Tmp_storage'
            
        if os.path.exists(self.direction_path / 'final'):
            self.final_results = self.direction_path / 'final'
        else:
            os.mkdir(self.direction_path / 'final')
            self.final_results = self.direction_path / 'final'
            
        self.geo_file = self.direction_path / 'final' / 'coordinate.csv'
        self.final_csv = self.direction_path / 'final' / 'final.csv'

        load_dotenv()

        os.environ['DIR_PATH'] =str(self.direction_path)
        os.environ['TMP_STORAGE'] = str(self.tmp_storage)
        os.environ['FINAL_RESULT'] = str(self.final_results)
        os.environ['GEO_FILE'] = str(self.geo_file)
        os.environ['FINAL_CSV'] = str(self.final_csv)
        
        #Next needed to add pathes with module to system path
        sys.path.append(self.direction_path/'tests')
        sys.path.append(self.direction_path/'vpn_check')
        sys.path.append(self.direction_path/'extra')
        sys.path.append(self.direction_path/'SQLFunc')

        # Check path to required files
        self.counter = 0

        self.HEADER = '\033[95m'
        self.OKBLUE = '\033[94m'
        self.OKCYAN = '\033[96m'
        self.OKGREEN = '\033[92m'
        self.WARNING = '\033[93m'
        self.FAIL = '\033[91m'
        self.ENDC = '\033[0m'
        self.BOLD = '\033[1m'
        self.UNDERLINE = '\033[4m'

        self.failed_url = []

    @staticmethod
    def write_in_file(path, message, wtype='a+', q=True):
        """
        Func for write some message to file
        :param wtype: type of python default file.write method
        :param q: bool, print err code ot not
        :param path: absolute path to necessary file (str type)
        :param message: data with message in string format (str type)
        :return: None (None type)
        """
        with open(path, wtype, encoding='UTF-8') as f:
            f.write(message)
            f.close()
            if not q:
                print(message + 'success writen on file!')

    @staticmethod
    def read_from_file(path):
        """
        Func for read some message from file
        :param path: absolute path to necessary file (str type)
        :return: message from data (str type)
        """
        if os.path.split(path)[1].split('.')[1] == 'csv':
            data = pd.read_csv(path, header=0, encoding='UTF-8')
            return data
        if os.path.split(path)[1].split('.')[1] == 'json':
            with open(path, 'r', encoding='UTF-8') as file:
                data = json.load(file)
                return data
        if os.path.split(path)[1].split('.')[1] == 'xlsx':
            data = pd.read_excel(path)
            return data
        else:
            with open(path) as f:
                data = f.read()
            return data

    def f_exist(self, file_name, file_loc=None):
        """
        Func for check file for his location File location can be updated
        from one of common values in File_Work path list or create by user
        :param file_name: name of searching file
        :param file_loc: location of needed file. If None function
        will be search in next list:[File_work.direction_path, File_work.direction_with_filename,
        File_work.path_with_real_data].
        :return: If file_loc is None - return dict where keys - file location,
        and values bool True if exist else False;
        if file_loc defined - return bool True if exist else False
        """
        if file_loc:
            exist = os.path.exists(os.path.join(file_loc, file_name))
            return exist
        else:
            find_file = {}
            for i in [self.direction_path,
                      self.path_with_data]:
                find_file.update({i: os.path.exists(os.path.join(i, file_name))})
            return find_file

    def f_copy_to(self, file_name, file_path_from, file_path_to):
        """
        Func for copy file to another direction
        :param file_name: str of scp file name
        :param file_path_from: dir, where file exist
        :param file_path_to: dir, where file will be created
        :return: None
        """
        try:
            data = self.read_from_file(os.path.join(file_path_from, file_name))
        except FileNotFoundError:
            raise BaseException("Didn't find file in directory")
        if self.f_exist(file_name, file_path_to):
            raise FileExistsError('File already exist')
        self.write_in_file(os.path.join(file_path_to, file_name), data)

    def read_txt_as_csv(self, path, header=True):
        with open(path, 'r') as f:
            data = f.read()
        tmp = []
        answer = []
        for i in data.split('\t'):
            if "\n" in i:
                answer.append(tmp)
                tmp = []
            else:
                tmp.append(i)
        answer = pd.DataFrame(answer)
        if header:
            answer.columns = answer.iloc[0]
            answer = answer.drop(0)
        return answer

    def env_change(self, key, value):
        """
        Change environment, which contains all hardcoded data of script.
        Automatically change environment of project
        :param key: str, name of this env
        :param value: str, value of {key} env
        :return: None
        """
        tmp = []
        env_arr = []
        for i in self.read_from_file(self.direction_path + '\\.env').split('\n'):
            if i[0] != '#':
                tmp.append(i.split('='))
        for i in tmp:
            if i[0] == key:
                i[1] = value
                env_arr.append('='.join(i))
            else:
                env_arr.append('='.join(i))
        self.write_in_file(self.direction_path + '\\.env', '\n'.join(env_arr), wtype='w')
        load_dotenv()

    def permission_correct(self, path, mode, set_user_log):
        """
        Change chmod of {path} file
        :param mode: int, mode in Unix-like format
        :param path: str, path of correct file
        :param set_user_log: str, username of account with permission problem
        :return: None
        """
        try:
            os.chmod(path, mode)
        except PermissionError:
            print("{}Permission Error: please, change user{}".format(self.WARNING,
                                                                     self.ENDC))
            print("{}Continue?{}".format(self.WARNING, self.ENDC))
            check = input("(Y/n)")
            if check.lower() in ['y', '\n', 'yes'] and os.name == "nt":
                log = input('Login:')
                exec(r'runas /profile /user:{} '
                     r'C:\Users\user\PycharmProjects\Image_recognise'
                     r'\Image_finder\req.py'.format(log))
                exec('icalc {} /grant /{}:{}'.format(
                    path, set_user_log, mode
                ))
            else:
                log = input('Login:')
                exec('su - {}'.format(log))
                exec('chmod {} {}'.format(mode, path))
