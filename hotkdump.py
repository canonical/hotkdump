#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import logging
from subprocess import run

#am sure will need all this later
from typing import Dict, List, Tuple, Union


"""
TODOS:

1) need rotom to figure out when a new vmcore is uploaded to files.canonical
and for which case, for automatically updating the case without someone needing
to manually run the script and pass in the casenum and vmcore name. 
This will need a cron job.

2) need to download the vmcore instead of current hardcoding.

3) need to handover hotkdump.out to athena for internal case update

4) can athena read from sfdc case (instead of just write as internal comment) 
and figure when a new vmcore gets uploaded, and read the full file path 
from there? This will need polling though.

5) how often to purge, do we immediately delete the vmcore after we send off 
the output file to athena? storage is an issue on rotom.. can we add more storage?

6) ...

"""


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
        fullcmd = command + args
        #print("executing", fullcmd)
        logging.info("executing %s", fullcmd)
        logging.info("in execute_cmd with command %s and args %s" , command,args)
        result = 0
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
        cmd = "./crash -s"
        args = " --osrelease " + str(vmcore) 
        output = self.execute_cmd(cmd , args,1)
        logging.info("got this output from execute_cmd %s",str(output))
        return str(output)

    def download_vmlinux(self, kernel_version: str):
        # see https://wiki.ubuntu.com/Debug%20Symbol%20Packages
        print("Downloading vmcore for kernel", kernel_version)
        logging.info("Downloading vmcore for kernel %s",kernel_version)
        cmd = "apt-get "
        kernel_version = kernel_version.rstrip()
        check_cwd = "./vmlinux-" + kernel_version
        if os.path.exists(check_cwd):
            print("% file already exists in cwd ",check_cwd)
            return "vmlinux-" + kernel_version
        elif os.path.exists("/lib/debug/boot/vmlinux-" + kernel_version):
            # this stuff really needs its own function so can be reused below
            print("vmlinux for % found in /lib/debug/boot", kernel_version)
            #move the debug file into cwd
            cmd = "cp "
            args = "/lib/debug/boot/" + "vmlinux-" + kernel_version 
            fullargs = args + " ."
            fullcmd = cmd + fullargs
            print(fullcmd)
            print("looking for", args)
            if os.path.exists(args.rstrip()):
                print("found")
                print(cmd+args)
                print("doing cp now")
                print(fullcmd)
                output = self.execute_cmd(cmd,fullargs,0)
                if output == 0:
                    print("output 0")
                    return "vmlinux-" + kernel_version
                else:
                    print("output of cp not 0")
            else:
                print("not exists??")
                return ""
            return "vmlinux-" + kernel_version
        else:
            # need to install the dbgsym
            args = "install -y linux-image-" + kernel_version + "-dbgsym"
            print(cmd + args)
            print("sending that cmd off for execution")
            output = self.execute_cmd(cmd, args,0)
            if output == 0:
                #move the debug file into cwd
                cmd = "cp "
                args = "/lib/debug/boot/" + "vmlinux-" + kernel_version 
                fullargs = args + " ."
                fullcmd = cmd + fullargs
                print(fullcmd)
                if os.path.exists(args):
                    print("doing cp now")
                    print(cmd+args)
                    output = self.execute_cmd(cmd,fullargs,0)
                    if output == 0:
                        print("output 0")
                        return "vmlinux-" + kernel_version
                    else:
                        print("output of cp not 0")
            else:
                print("output of apt-get install not 0")
                return ""
        
def main():
    hotk = hotkdump()

    logging.info("%s is hotk.vmcore",hotk.vmcore)
    kernel_version = hotk.get_kernel_version(str(hotk.vmcore))
    logging.info("%s is kernel_version",kernel_version)
    vmlinux = hotk.download_vmlinux(kernel_version)
    if vmlinux == "": 
        print("got empty vmlinux")
        ## goto out? :-X
    else:
        # assuming vmcore exists in cwd for now
        # can figure later how to download it from files.canonical given a 
        # casenum (for athena) and the name or full files.canonical path of the vmcore
        dump = hotk.vmcore
        print(dump)
        print("is dump\n")
        print(vmlinux)
        print("is vmlinux")
        args = str(dump) + " " + str(vmlinux)
        print("\n and args are")
        print(args)
        logging.info("args to main are ...")
        logging.info(args)

        # todo move cmd to a class variable
        # remove the -s if you want to see console output 
        # of what crash is upto, in case there's a failure
        cmd = "./crash -s "
        print("Loading vmcore into crash.. please wait..")
        output = hotk.execute_cmd(cmd,args,0)
        file_crashrc = open('/home/hotkdump/.crashrc', 'r')
        all_crashrc_commands = file_crashrc.readlines()
        print("Collected output of.. \n")
        for line in all_crashrc_commands:
            if 'echo' not in line and 'quit' not in line:
                line_to_print = line.split(">")[0]
                print(line_to_print)
        print("\nSee hotkdump.log for logs")
        print("See hotkdump.out for output")

if __name__=="__main__":
    main()


