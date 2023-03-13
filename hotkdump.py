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

$ strings dump.202211220833 | head -n5
KDUMP
hc-hrrijf1-j304c7y6
5.15.0-52-generic
#58~20.04.1-Ubuntu SMP Thu Oct 13 13:09:46 UTC 2022
x86_64

$ pull-lp-ddebs linux-image-unsigned-5.15.0-52-generic 5.15.0-52.58~20.04.1
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

$ mkdir extract_folder
$ dpkg -x linux-image-unsigned-5.15.0-52-generic-dbgsym_5.15.0-52.58~20.04.1_amd64.ddeb extract_folder/

And pick it up from extract_folder/usr/lib/debug/boot/ 


Can also use this approach suggested by @mkg++

import sys

def seek_to_first_non_nul(f):
    pos = f.tell()
    while f.read(1) == b'\x00':
        pos = f.tell()
        pass
    f.seek(pos)

def readcstr(f):
    buf = str()
    while True:
        b = f.read(1)
        if (b is None) or (b == b'\x00'):
            seek_to_first_non_nul(f)
            return str(''.join(buf))
        else:
            buf += b.decode('ascii')

with open(sys.argv[1], 'rb') as fd:
    magic = fd.read(8)
    print(magic)
    if not magic == b'KDUMP   ':
        print("not a kernel crash dump file")
        sys.exit(-1)
    version = int.from_bytes(fd.read(4), byteorder='little')
    print("Version: {}".format(version))
    print("system {}".format(readcstr(fd)))
    print("node {}".format(readcstr(fd)))
    print("release {}".format(readcstr(fd)))
    print("version {}".format(readcstr(fd)))
    print("machine {}".format(readcstr(fd)))
    print("domain {}".format(readcstr(fd)))

$python3 parse-fields.py dump.202212171954 
b'KDUMP   '
Version: 6
system x
node hc-hrrijf1-j304c7y7
release 5.15.0-52-generic
version #58~20.04.1-Ubuntu SMP Thu Oct 13 13:09:46 UTC 2022
machine x86_64
domain (none)

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
    filename = ""

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
        with open("hotkdump.out","w") as hotkdump_out:
            #hotkdump_out.write("!echo \"Output of sys\\n\"")
            hotkdump_out.close()
        with open(".crashrc","w") as crashrc_file:
            crashrc_file.write("!echo \"Output of sys\\n\" >> hotkdump.out\n")
            crashrc_file.write("sys >> hotkdump.out\n")
            crashrc_file.write("!echo \"\\nOutput of bt\\n\" >> hotkdump.out\n")
            crashrc_file.write("bt >> hotkdump.out\n")
            crashrc_file.write("!echo \"\\nOutput of log with audit messages filtered out\\n\" >> hotkdump.out\n")
            crashrc_file.write("log | grep -vi audit >> hotkdump.out\n")
            crashrc_file.write("!echo \"\\nOutput of kmem -i\\n\" >> hotkdump.out\n")
            crashrc_file.write("kmem -i >> hotkdump.out\n")
            crashrc_file.write("!echo \"\\nOutput of dev -d\\n\" >> hotkdump.out\n")
            crashrc_file.write("dev -d >> hotkdump.out\n")
            crashrc_file.write("!echo \"\\nOutput of mount\\n\" >> hotkdump.out\n")
            crashrc_file.write("mount >> hotkdump.out\n")
            crashrc_file.write("!echo \"\\nOutput of files\\n\" >> hotkdump.out\n")
            crashrc_file.write("files >> hotkdump.out\n")
            crashrc_file.write("!echo \"\\nOutput of vm\\n\" >> hotkdump.out\n")
            crashrc_file.write("vm >> hotkdump.out\n")
            crashrc_file.write("!echo \"\\nOldest blocked processes\\n\" >> hotkdump.out\n")
            crashrc_file.write("ps -m | grep UN | tail >> hotkdump.out\n")
            crashrc_file.write("quit >> hotkdump.out\n")
        crashrc_file.close()
        """
        The .crashrc file we generate should look like

		!echo "Output of sys\n" >> hotkdump.out
		sys >> hotkdump.out
		!echo "\nOutput of bt\n" >> hotkdump.out
		bt >> hotkdump.out
		!echo "\nOutput of log with audit messages filtered out\n" >> hotkdump.out
		log | grep -vi audit >> hotkdump.out
		!echo "\nOutput of kmem -i\n" >> hotkdump.out
		kmem -i >> hotkdump.out
		!echo "\nOutput of dev -d\n" >> hotkdump.out
		dev -d >> hotkdump.out
		!echo "\nOldest blocked processes\n" >> hotkdump.out
		ps -m | grep UN | tail >> hotkdump.out
		quit >> hotkdump.out
        """

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
        minor_version = ""
        print("Downloading vmcore for kernel", kernel_version)
        logging.info("Downloading vmcore for kernel %s",kernel_version)
        cmd = "apt-get "
        kernel_version = kernel_version.rstrip()
        check_cwd = "./vmlinux-" + kernel_version
        # need to install the dbgsym
        # get the minor release using strings
        print("installing dbgsym")
        strings_cmd = "strings"
        strings_args = " " + self.vmcore + " | head -n10"
        result = self.execute_cmd(strings_cmd, strings_args, 1)
        print("strings run on the vmcore has this..\n")
        print(result)
        strings_lines = result.splitlines()
        if strings_lines[0].strip() == "KDUMP": #need more checks here?
            print("found the KDUMP string at the beginning.")
            for i in strings_lines:
              if i.startswith("#") and "SMP" in i:
                  minor_version = i.split()[0]
                  minor_version = minor_version.split("-")[0].lstrip("#")
                  print("minor version is.." , minor_version)
                  break
        else:
            print("Could not match kdump string\n")
            exit()

        pull_lp_cmd = "pull-lp-ddebs"
        # for eg pull-lp-ddebs linux-image-unsigned-5.15.0-52-generic 5.15.0-52.58~20.04.1
        kernel_version_minus_generic = kernel_version.split("-generic")[0] 
        print("kernel version minus generic is",kernel_version_minus_generic)
        pull_lp_args = " linux-image-unsigned-" + kernel_version + " " + kernel_version_minus_generic + "." + minor_version
        fullcmd = pull_lp_cmd + pull_lp_args
        print("command is.. " , fullcmd)
        #running this from here as an exception due to the stderr stuff
        result = subprocess.run(fullcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result)
        print("just printed result")
        if result.returncode == 0:
            split_result = str(result.stdout).split("Downloading")[1]
            #print(split_result)
            self.filename = split_result.lstrip().split()[0]
            print("filename is ",self.filename)
            cmd = "mkdir"
            args = " extract_folder"
            output = self.execute_cmd(cmd, args,0)
            cmd = "dpkg"
            args = " -x " + self.filename + " extract_folder"
            print("executing this command now ",cmd + args)
            output = self.execute_cmd(cmd,args,0)
            return "extract_folder/usr/lib/debug/boot/vmlinux-" + kernel_version

    def cleanup(self, vmlinux):
        cmd = "rm -rf "
        args = "extract_folder" + " .crashrc " + self.filename
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
        print("dump is .. \n",dump)
        print("and vmlinux is " , vmlinux)
        args = str(dump) + " " + str(vmlinux)
        print("\n and args are")
        print(args)
        logging.info(args)

        # todo move cmd to a class variable
        # remove the -s if you want to see console output 
        # of what crash is upto, in case there's a failure
        cmd = "./crash -s "
        print("Loading vmcore into crash.. please wait..")
        output = hotk.execute_cmd(cmd,args,0)
        file_crashrc = open('.crashrc', 'r')
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


