#python imports
import sys
import os
import subprocess
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Executes host -a against the target.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    host_output_data = ''
    output = logdir + 'host.txt'

    FI = fileio()

    print '\r\n[*] Running Host against: ' + target.target

    subproc = subprocess.Popen('host -a ' + target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for host_data in subproc.stdout.readlines():
        if (debug == True):
            print '[DEBUG]: ' + host_data 
        host_output_data += host_data 
              
    try:        
        FI.WriteLogFile(output, host_output_data)
        print colored('[*] Host data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Host data has been generated to file here: <a href=\"' + output + '\"> Host Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
    except:
        print colored('[x] Unable to write Host data to file', 'red', attrs=['bold'])  
        if (logging == True):
            newlogentry = 'Unable to write Host data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
