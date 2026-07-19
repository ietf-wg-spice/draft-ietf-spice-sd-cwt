#!/usr/bin/env python3
import os
import sys

from enum import Enum
class Role(Enum):
    Issuer = 1
    Holder = 2
    Verifier = 3

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def ok_or_fail(worked):
    if worked:
        return f'{bcolors.OKGREEN}[OK]{bcolors.ENDC}'
    else:
        return f'{bcolors.FAIL}[FAILED]{bcolors.ENDC}'

def runone(test_case, input_role, input_impl, base, directory,
           issuer_priv=None, issuer_options=None):
    # exammples
    #    test_case = "shipping-manifest4"
    #    input_role = Role.Holder
    #    input_impl = foobar (output of an implementation's `target` command)
    #    base = '/home/user/sd-cwt-testing/interop'
    #    directory = `{base}/tests/I=foobar_H=baz_V=foobar/2026-07-18T15:21:29`

    # need access to:
    #  - `interop/implementations/{input_impl}/{input_role}`
    #  - `interop/test_cases/{test_case}`
    #from subprocess import run, CompletedProcess
    import subprocess

    # get current directory, derive base directory
    #base = os.path.commonprefix()

    roles = {
      Role.Issuer : "issue",
      Role.Holder : "holder",
      Role.Verifier : "verify"
    }
    role = roles[input_role]
    arg0 = f"{base}/implementations/{input_impl}/{role}"
    logfile = open(f"{directory}/{test_case}-{role}.log", 'w')
    # add more args
    match input_role:
        case Role.Issuer:
            if issuer_priv is None:
                raise Exception("missing Issuer private key")
            args = [ arg0, issuer_priv ]
            if issuer_options is not None:
                arg += issuer_options
            infile=open(f'{base}/test_cases/{test_case}/origclaims.cbor', 'rb')
            outfile=open(f'{directory}/{test_case}.sdcwt.cbor', 'wb')
        case Role.Holder:
            infile=open(f'{directory}/{test_case}.sdcwt.cbor', 'rb')
            outfile=open(f'{directory}/{test_case}.kbt.cbor', 'wb')
        case Role.Verifier:
            infile=open(f'{directory}/{test_case}.origclaims.cbor', 'rb')
            outfile=open(f'{directory}/{test_case}.sdcwt.cbor', 'wb')

    result = subprocess.run(args, stdin=infile, stdout=outfile, stderr=logfile, cwd=directory)

    if result.returncode == 0:
        print(f"{args} {ok_or_fail(1)}")
    else:
        print(f"{args} {ok_or_fail(0)}")
    return result.returncode


if __name__ == "__main__":
    from datetime import datetime, timezone
    utc_now = datetime.now(timezone.utc)
    timestamp = utc_now.strftime("%Y-%m-%dT%H:%M:%S")
    base = "/Users/rohan/src/ietf/ietf-wg-spice/draft-ietf-spice-sd-cwt/interop"
    directory = base + "/tests/I=dumb_H=dumb/" + timestamp
    os.makedirs(directory, exist_ok=True)

    test_case = "shipping_manifest4"
    input_role = Role.Issuer
    input_impl = "dumb"
    issuer_priv = base + '/test_cases/' + test_case + '/issuer_priv.pem'
    runone(test_case, input_role, input_impl, base, directory,
           issuer_priv=issuer_priv, issuer_options=None)




# subprocess.run(args, *, stdin=None, input=None, stdout=None, stderr=None, capture_output=False, shell=False, cwd=None, timeout=None, check=False, encoding=None, errors=None, text=None, env=None, universal_newlines=None, **other_popen_kwargs)

# subprocess.Popen(args, bufsize=-1, executable=None, stdin=None, stdout=None, stderr=None, preexec_fn=None, close_fds=True, shell=False, cwd=None, env=None, universal_newlines=None, startupinfo=None, creationflags=0, restore_signals=True, start_new_session=False, pass_fds=(), *, group=None, extra_groups=None, user=None, umask=-1, encoding=None, errors=None, text=None, pipesize=-1, process_group=None)
#from select import select
#from subprocess import Popen, PIPE
#    Popen(args, bufsize=0, stdin=infile, close_fds=False)
#    
#    with Popen(arg, stdout=PIPE, stderr=PIPE) as p:
#        readable = {
#            p.stdout.fileno(): sys.stdout.buffer, # log separately
#            p.stderr.fileno(): sys.stderr.buffer,
#        }
#        while readable:
#            for fd in select(readable, [], [])[0]:
#                data = os.read(fd, 1024) # read available
#                if not data: # EOF
#                    del readable[fd]
#                else: 
#                    readable[fd].write(data)
#                    readable[fd].flush()



