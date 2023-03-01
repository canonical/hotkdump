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
    def __init__(self):
    #have some class variables here to make things easy
        print("in init...")

    def execute_cmd(self, command: str, args: str , run_or_check: int) -> Tuple[str, int]:
        print("in execute_cmd")
        print(command)
        print(args)
        return_code = 0
        output = None
        try:
            fullcmd = command + args
            print(fullcmd)
            if run_or_check == 1:
                result = subprocess.check_output(fullcmd, text=True,shell=True)
            else:
                result = subprocess.call(fullcmd, text=True, shell=True)

            #cmd_to_execute = run(command, stdout=PIPE, stderr=STDOUT, input=args.encode(), check=False)
            print(result)
            #output = cmd_to_execute.stdout
        except OSError as err:
            print("OSError")
            print(err)
        except Exception as err:
            print("exception")
            print(err)

        return result

    def get_kernel_version(self, vmcore):
        print("in get_kernel_version")
        cmd = "crash"
        args = " --osrelease " + str(vmcore) 
        output = self.execute_cmd(cmd,args,1)
        print("got this output from execute_cmd")
        print(str(output))
        return str(output)

    def download_vmlinux(self, kernel_version: str):
        # stub, this returns the filename it downloads and keeps in cwd
        # hardcode for now
        return "vmlinux-5.15.0-52-generic"
        
def main():
    print("in main..")
    logfile = open("/tmp/hotkdump_log", "w")
    logfile.write("starting logs")
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--casenum",  required=True, help="SF case number")
    ap.add_argument("-d", "--dump", required=True, help="name of vmcore file")
    args = vars(ap.parse_args())

    casenum = args['casenum']
    vmcore = args['dump']

    hotk = hotkdump()

    kernel_version = hotk.get_kernel_version(str(vmcore))
    print(kernel_version)
    vmlinux = hotk.download_vmlinux(kernel_version)

    # taking from args for now, assuming vmcore exists in cwd for now
    # can figure later how to download it from files.canonical given a 
    # casenum (for athena) and the name or full files.canonical path of the vmcore
    dump = vmcore

    cmd = "./crash " 
    args = str(dump) + " " + str(vmlinux)
    print(args)
    output = hotk.execute_cmd(cmd,args,0)

if __name__=="__main__":
    main()


