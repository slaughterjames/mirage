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
Type: Passive - Description: Executes Dig against the target.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    dig_output_data = ''
    output = POE.logdir + 'Dig.txt'

    FI = fileio()

    print '\r\n[*] Running Dig against: ' + POE.target

    subproc = subprocess.Popen('dig -t NS ' + POE.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for dig_data in subproc.stdout.readlines():
        if (POE.debug == True):
            print '[DEBUG]: ' + dig_data 
        dig_output_data += dig_data 
              
    try:        
        FI.WriteLogFile(output, dig_output_data)
        print colored('[*] Dig data has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'Dig data has been generated to file here: <a href=\"' + output + '\"> Dig Output </a>'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'True,'
    except:
        print colored('[x] Unable to write Dig data to file', 'red', attrs=['bold'])  
        if (POE.logging == True):
            newlogentry = 'Unable to write Dig data to file'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'False,'
        return -1

    return 0
