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
Type: Info - Description: Executes a grep against the current TorDNSEL list of exit nodes.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    tor_output_data = ''

    if (POE.ip == False):
        print colored('\r\n[-] Unable to execute ToR Node IP grep - target must be an IP - skipping.', 'yellow', attrs=['bold']) 
        if (POE.logging == True):
            newlogentry = 'Unable to execute ToR Node IP grep - target must be an IP - skipping.'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    FI = fileio()

    print '\r\n[*] Running ToR Node grep against: ' + POE.target

    subproc = subprocess.Popen('grep ' + POE.target + ' /opt/mirage/feeds/ToR_Exits.txt', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for tor_data in subproc.stdout.readlines():
        if (tor_data != ''):
            print colored('[-] Target is or was a ToR exit node...', 'red', attrs=['bold'])
        if (POE.debug == True):
            print '[DEBUG]: ' + tor_data 
        tor_output_data += tor_data 
    
    if (tor_output_data != ''):                      
        if (POE.logging == True):
            newlogentry = '<strong>ToR: Target is or was a ToR exit node...</strong>'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'True,'   
    else:
        print colored('[-] Target does not appear to be a ToR exit node.', 'yellow', attrs=['bold'])    
        print colored('[x] ToR data not written to file', 'red', attrs=['bold'])
        POE.csv_line += 'False,' 

    return 0
