hotkdump

Hotkdump is a python script on rotom that downloads and analyzes a vmcore after the script is run on rotom passing the casenum and vmcore path as arguments. (This can be automated in time, i.e if we have a way to determine that there has been a new vmcore uploaded on files.canonical, and the casenum it is associated with, there could be a trigger script to kickoff the hotkdump script on rotom passing the right arguments to it)

Hotkdump will then (I am sure there will be more subtasks in here)
download the vmcore into a new folder on rotom in /hotkdump/cases/$CASENUM/$i++, (say /hotkdump/cases/00345677/1/coredump.tar.gz), 
extract the vmcore using tar/unzip/bunzip/etc (if needed),
verify its a valid core file using “file”, etc ,
determine the kernel version (‘crash –osrelease dump.core’, or ‘strings dump.core | grep OSRELEASE=’, or even ‘od -N 300 --strings dump.core’) ,
download the debugsyms using the approach in https://wiki.ubuntu.com/Debug%20Symbol%20Packages (might be an easier way to install the debugsyms?) ,
pickup the (most recent installed) debugsym from /lib/debug/boot ,
spawn a shell in which to run crash with the vmcore and debugsyms as args (remember to load modules needed by the vmcore too, so first run mod to get that list) ,
log to a file (for now its hotkdump.out in the cwd) the outputs of basic commands like bt, kmem -i, log, sys, dev -d, etc. ,
pass the casenum and the file to athena to make an internal comment on the case.

(cleanup/logging)
Purge older dumps and debugsyms routinely (every 2 weeks?)
Log all cmd outputs to a log file in the same folder.

Later we could extend crash with pykdump and additionally collect dmshow, scsishow, and other pykdump commands in hotkdump, that allow easy debugging of vmcores.

The nice thing about this is the vmcores are also already setup and ready for analysis for manual inspection on rotom. We will use the upstream crash (which we will git clone and build on rotom and use that crash, instead of apt installed crash. (or the snap if there is one?).

One of the potential future ideas for hotkdump is to have use-cases programmed into it to check the vmcore for, like how hotsos would check a sosreport for certain conditions. But this is non trivial, (apart from checking output of “log” say for certain known bugs or error strings, or looking at sys or kmem -i to determine OOM, for eg.)

Older stored kdumps and debugsyms will be purged, say every 2 weeks unless you need it for manual analysis, so we need a way to stop those being auto purged, say just touch a certain file in the folder (NOPURGE) which if exists, prevents purge by hotkdump. The purging has to be a cron job I suppose..



