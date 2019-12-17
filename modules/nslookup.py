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
Type: Passive - Description: Executes an NSLookup against the target.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    nsl_output_data = ''
    not_found_flag = 0
    output = POE.logdir + 'NSLookup.txt'

    FI = fileio()

    print '\r\n[*] Running NSLookup against: ' + POE.target

    subproc = subprocess.Popen('nslookup -type=any ' + POE.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for nsl_data in subproc.stdout.readlines():
        if (POE.debug == True):
            print '[DEBUG]: ' + nsl_data 
        nsl_output_data += nsl_data
        if (nsl_output_data.find('** server can\'t find')!= -1): 
            not_found_flag = 1  
              
    try:
        if (not_found_flag == 1):
            print colored('[x] NSLookup: Server can\'t find host.  NSLookup data not written to file.', 'red', attrs=['bold'])
            if (POE.logging == True):
                newlogentry = 'NSLookup: Server can\'t find host.  NSLookup data not written to file.'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
                POE.csv_line += 'False,'
        else:        
            FI.WriteLogFile(output, nsl_output_data)
            print colored('[*] NSLookup data has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
            if (POE.logging == True):
                newlogentry = 'NSLookup data has been generated to file here: <a href=\"' + output + '\"> NSLookup Output </a>'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
                POE.csv_line += 'True,'
    except:
        print colored('[x] Unable to write NSLookup data to file', 'red', attrs=['bold']) 
        if (POE.logging == True):
            newlogentry = 'Unable to write NSLookup data to file'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'False,'
        return -1

    return 0
