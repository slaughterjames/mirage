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
Type: Passive - Description: Executes host -a against the target.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    host_output_data = ''
    not_found_flag = 0
    output = POE.logdir + 'host.txt'

    FI = fileio()

    print '\r\n[*] Running Host against: ' + POE.target

    subproc = subprocess.Popen('host -a ' + POE.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for host_data in subproc.stdout.readlines():
        if (POE.debug == True):
            print '[DEBUG]: ' + host_data 
        host_output_data += host_data
        if (host_output_data.find('not found:')!= -1): 
            not_found_flag = 1  
              
    try:
        if (not_found_flag == 1):
            print colored('[x] Host: host not found.  Host data not written to file.', 'red', attrs=['bold'])
            if (POE.logging == True):
                newlogentry = 'Host: host not found.  Host data not written to file.'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
                POE.csv_line += 'False,'
        else:
            FI.WriteLogFile(output, host_output_data)
            print colored('[*] Host data has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
            if (POE.logging == True):
                newlogentry = 'Host data has been generated to file here: <a href=\"' + output + '\"> Host Output </a>'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
                POE.csv_line += 'True,'
    except:
        print colored('[x] Unable to write Host data to file', 'red', attrs=['bold'])  
        if (logging == True):
            newlogentry = 'Unable to write Host data to file'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'False,'
        return -1

    return 0
