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

2) need to download the vmcore debugsym using this approach, 

nikhil@nikhil-XPS-15-7590:~/hotkdump/hotkdump/202211220833$ strings dump.202211220833 | head -n5
KDUMP
hc-hrrijf1-j304c7y6
5.15.0-52-generic
#58~20.04.1-Ubuntu SMP Thu Oct 13 13:09:46 UTC 2022 <---- append this as below
x86_64

nikhil@nikhil-XPS-15-7590:~/hotkdump/hotkdump/202211220833$ pull-lp-ddebs linux-image-unsigned-5.15.0-52-generic 5.15.0-52.58~20.04.1
Source package lookup failed, trying lookup of binary package linux-image-unsigned-5.15.0-52-generic
Using source package 'linux-hwe-5.15' for binary package 'linux-image-unsigned-5.15.0-52-generic'
Found linux-hwe-5.15 5.15.0-52.58~20.04.1 in focal
Pulling only binary package 'linux-image-unsigned-5.15.0-52-generic'
Use package name 'linux-hwe-5.15' to pull all binary packages
Please wait, this may take some time...
Download Error: 503 Server Error: Service Unavailable for url: http://ddebs.ubuntu.com/pool/main/l/linux-hwe-5.15/linux-image-unsigned-5.15.0-52-generic-dbgsym_5.15.0-52.58~20.04.1_amd64.ddeb
Downloading linux-image-unsigned-5.15.0-52-generic-dbgsym_5.15.0-52.58~20.04.1_amd64.ddeb from launchpadlibrarian.net (1295.525 MiB)
[=====================================================>]100%

Then extract it in a folder like so,

nikhil@nikhil-XPS-15-7590:~/hotkdump/hotkdump/202211220833$ mkdir extract_folder
nikhil@nikhil-XPS-15-7590:~/hotkdump/hotkdump/202211220833$ dpkg -x linux-image-unsigned-5.15.0-52-generic-dbgsym_5.15.0-52.58~20.04.1_amd64.ddeb extract_folder/

And pick it up from extract_folder/usr/lib/debug/boot/ 

3) need to handover hotkdump.out to anyone who is consuming this tool, one consumer for eg 
will update the case with an internal comment showing the auto analysis

5) how often to purge, do we immediately delete the vmcore after we send off 
the output file to athena? storage is an issue on rotom.. can we add more storage?

6) leverage the filemover, and think about this as a generic application or a library

"""


class hotkdump:
    vmcore = ""
    casenum = ""
    cmd = "" 
    used_apt_get=0
    used_pull_lp_ddebs=0

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
                result = subprocess.call(fullcmd, text=True, shell=True )

            logging.info("result is.. %s",result)
        except OSError as err:
            print("OSError")
            print(err)
        except Exception as err:
            print("exception")
            print(err)

        if result != 0 and run_or_check == 0:
            logging.info("result of command %s was non 0!!!", fullcmd)
            print(result)
            exit()
        else:
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
            print("file already exists in cwd .. found.. ",check_cwd)
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
                return "vmlinux-" + kernel_version
            else:
                print("such path not exist??")
                return ""
            return "vmlinux-" + kernel_version
        else:
            # need to install the dbgsym
            # first try with pull-lp-ddebs
            pull_lp_cmd = "pull-lp-ddebs"
            pull_lp_args = " linux-image-unsigned-" + kernel_version
            fullcmd = pull_lp_cmd + pull_lp_args
            print("sending command.. " , fullcmd)
            #result = subprocess.check_output(fullcmd)
            #running this from here as an exception due to the stderr stuff
            result = subprocess.run(fullcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(result)
            print("just printed result")
            if result.returncode == 0:
                used_pull_lp_ddebs=1 # so we can delete the folder at exit
                split_result = str(result.stdout).split("Downloading")[1]
                print(split_result)
                filename = split_result.lstrip().split()[0]
                print(filename)
                cmd = "mkdir"
                args = " extract_folder"
                output = self.execute_cmd(cmd, args,0)
                cmd = "dpkg"
                args = " -x " + filename + " extract_folder"
                print("executing this command now ",cmd + args)
                output = self.execute_cmd(cmd,args,0)
                return "extract_folder/usr/lib/debug/boot/vmlinux-" + kernel_version
            else:
                #try apt-get install and pickup lib from /lib/debug/boot
                used_apt_get=1 #so we can delete the file from cwd at exit time
                cmd = "apt-get "
                args = "install -y linux-image-" + kernel_version + "-dbgsym"
                print(cmd + args)
                print("sending that cmd off for execution")
                output = self.execute_cmd(cmd, args,0)
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
                    return "vmlinux-" + kernel_version
                else:
                    print("did not find the dbgsym in /lib/debug/boot/ even though apt-get seemed to work!")
                    return ""
    def cleanup(self, vmlinux):
        cmd = "rm -rf "
        if self.used_apt_get == 1:
            args = vmlinux
            output = hotk.execute_cmd(cmd,args,0)
            cmd = "apt-remove" 
            args = "linux-image-" + vmlinux + "-dbgsym"
            print("sending off this command now to remove the debugsym package",cmd+args)
            output = hotk.execute_cmd(cmd,args,0)
        elif self.used_pull_lp_ddebs == 1:
            args = "extract_folder"
            self.execute_cmd(cmd,args,0)
        print("done with cleanup")
        
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
        print("got this vmlinux from the function ",vmlinux)
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
        hotk.cleanup(vmlinux)


if __name__=="__main__":
    main()


