import subprocess as sp
import time
import threading


si = sp.STARTUPINFO
si = sp.STARTUPINFO(wShowWindow=1)


def cmd_spawner():
    proc = sp.Popen(r'cmd', creationflags=sp.CREATE_NEW_CONSOLE,
                stdin=sp.PIPE, stdout=sp.PIPE)
    #proc.communicate(input=b'explorer.exe\n')
def main():
    thread = threading.Thread(target=cmd_spawner())

    thread.daemon = True
    thread.start()
    time.sleep(1)

    if thread.isAlive():
        threading.settrace(cmd_spawner())
