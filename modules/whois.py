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
Queries the WhoIs information for a target
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    whois_dump = ''
    whois_output_data = ''
    output = logdir + 'WhoIs.txt'

    FI = fileio()

    subproc = subprocess.Popen('whois ' + target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for whois_data in subproc.stdout.readlines():
         whois_output_data += whois_data
         if  (debug == True):
             print whois_data    

    try:        
        FI.WriteLogFile(output, whois_output_data)
        print colored('[*] WhoIs data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'WhoIs file has been generated to file here: <a href=\"' + output + '\"> WhoIs Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
    except:
        print colored('[x] Unable to write whois data to file', 'red', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to whois strings data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
