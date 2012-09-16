import subprocess
import os
import sys
import traceback

from socialscan.config import loadDefaultConfig

def main():
    processes = []

    try:
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        processes.append(subprocess.Popen([sys.executable, "sdmanager.py"]))
        processes.append(subprocess.Popen([sys.executable, "rpcmanager.py"]))
        processes.append(subprocess.Popen([sys.executable, "webserver.py"]))
        processes.append(subprocess.Popen(["C:/squid/sbin/squid.exe"]))
        raw_input("press enter to stop the system")
    finally:
        for process in processes:
            try:
                process.terminate()
                process.kill()
            except:
                traceback.print_exc()
        for process in processes:
            try:
                process.wait()
            except:
                traceback.print_exc()
        raise

if __name__ == "__main__":
    main()
