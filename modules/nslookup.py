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
Executes an NSLookup against the target.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    nsl_output_data = ''
    output = logdir + 'NSLookup.txt'

    FI = fileio()

    print '[*] Running NSLookup against: ' + target.target

    subproc = subprocess.Popen('nslookup -type=any ' + target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for nsl_data in subproc.stdout.readlines():
        if (debug == True):
            print '[DEBUG]: ' + nsl_data 
        nsl_output_data += nsl_data 
              
    try:        
        FI.WriteLogFile(output, nsl_output_data)
        print colored('[*] NSLookup data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'NSLookup data has been generated to file here: <a href=\"' + output + '\"> NSLookup Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
    except:
        print colored('[x] Unable to write NSLookup data to file', 'red', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to write NSLookup data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
