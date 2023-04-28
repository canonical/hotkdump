hotkdump is a tool that takes a SF casenum and a downloaded vmcore as inputs and produces a hotkdump.out file
containing information extracted from the vmcore, which helps understand root causes of kernel panics or hangs. 

See how_to_run_and_output for a basic manual run. 

## Running tests

```sh
    python3 -m pytest
```

## TODOs

1) need to figure out when a new vmcore is uploaded to files.canonical
and for which case, for automatically updating the case

2) leverage the filemover, and think about this as a generic application or a library

3) update cases with a internal comment of a link to hotkdump.out output