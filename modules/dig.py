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
Executes Dig against the target.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    dig_output_data = ''
    output = logdir + 'Dig.txt'

    FI = fileio()

    print '[*] Running Dig against: ' + target.target

    subproc = subprocess.Popen('dig ' + target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for dig_data in subproc.stdout.readlines():
        if (debug == True):
            print '[DEBUG]: ' + dig_data 
        dig_output_data += dig_data 
              
    try:        
        FI.WriteLogFile(output, dig_output_data)
        print colored('[*] Dig data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Dig data has been generated to file here: <a href=\"' + output + '\"> Dig Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
    except:
        print colored('[x] Unable to write Dig data to file', 'red', attrs=['bold'])  
        if (logging == True):
            newlogentry = 'Unable to write Dig data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
