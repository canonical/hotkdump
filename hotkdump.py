#!/usr/bin/env python3
import argparse
import os
import sys
import time
import subprocess
import pexpect
import logging
import re

from subprocess import run

#am sure will need all this later
from typing import Dict, List, Tuple, Union


class hotkdump:
    vmcore = ""
    casenum = ""
    cmd = "" 

    def __init__(self):
        logging.basicConfig(filename='hotkdump.log', level=logging.INFO)

        logging.info("starting logs")
        logging.info("in init..")
        ap = argparse.ArgumentParser()
        ap.add_argument("-c", "--casenum",  required=True, help="SF case number")
        ap.add_argument("-d", "--dump", required=True, help="name of vmcore file")
        args = vars(ap.parse_args())
        self.casenum = args['casenum']
        self.vmcore = args['dump']
        logging.info('self.vmcore is %s', self.vmcore)

    def execute_cmd(self, command: str, args: str , run_or_check: int) -> Tuple[str, int]:
        logging.info("in execute_cmd with command %s and args %s" , command,args)
        return_code = 0
        output = None
        try:
            fullcmd = command + args
            logging.info("fullcmd is %s",fullcmd)
            if run_or_check == 1:
                result = subprocess.check_output(fullcmd, text=True,shell=True)
            else:
                result = subprocess.call(fullcmd, text=True, shell=True)

            logging.info("result is.. %s",result)
        except OSError as err:
            print("OSError")
            print(err)
        except Exception as err:
            print("exception")
            print(err)

        return result

    def get_kernel_version(self, vmcore):
        logging.info("in get_kernel_version with vmcore %s", vmcore)
        args = " --osrelease " + str(vmcore) 
        cmd = "./crash"
        output = self.execute_cmd(cmd , args,1)
        logging.info("got this output from execute_cmd %s",str(output))
        return str(output)

    def download_vmlinux(self, kernel_version: str):
        # stub, this returns the filename it downloads and keeps in cwd
        # https://wiki.ubuntu.com/Debug%20Symbol%20Packages
        # hardcode for now
        return "vmlinux-5.15.0-52-generic"
        
def main():
    hotk = hotkdump()

    logging.info("%s is hotk.vmcore",hotk.vmcore)
    kernel_version = hotk.get_kernel_version(str(hotk.vmcore))
    logging.info("%s is kernel_version",kernel_version)
    vmlinux = hotk.download_vmlinux(kernel_version)


    # taking from args for now, assuming vmcore exists in cwd for now
    # can figure later how to download it from files.canonical given a 
    # casenum (for athena) and the name or full files.canonical path of the vmcore
    dump = hotk.vmcore
    args = str(dump) + " " + str(vmlinux)
    logging.info("args to main are ...")
    logging.info(args)

    #todo move cmd to a class variable
    cmd = "./crash "
    output = hotk.execute_cmd(cmd,args,0)

if __name__=="__main__":
    main()


