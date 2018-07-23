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
Executes a grep against the top 1 million Internet domains on Alexa.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    alx_output_data = ''
    output = logdir + 'Alexa.txt'

    if ((target.ip == True) or (target.url == True)):
        print colored('\r\n[-] Unable to execute Alexa module - target must be a domain - skipping.', 'yellow', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to execute Alexa module - target must be a domain - skipping.'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1   

    FI = fileio()

    print '\r\n[*] Running Alexa grep against: ' + target.target

    subproc = subprocess.Popen('grep ' + target.target + ' /opt/mirage/feeds/top-1m.csv', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for alx_data in subproc.stdout.readlines():
        if (alx_data != ''):
            target.alexa = True
            print colored('[-] Target appears in the Alexa rankings', 'yellow', attrs=['bold'])            
        if (debug == True):
            print '[DEBUG]: ' + alx_data 
        alx_output_data += alx_data 
    
    if (alx_output_data != ''):                      
        print colored('[-] Target does appear in the Alexa rankings.', 'green', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Target does appear in the Alexa rankings.'
            LOG.WriteLog(logdir, target.target, newlogentry)
    else:
        print colored('[-] Target does not appear in the Alexa rankings.  This could be a malicious indicator.', 'red', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Target does not appear in the Alexa rankings.  <strong>This could be a malicious indicator.</strong>'
            LOG.WriteLog(logdir, target.target, newlogentry)    
        print colored('[x] Alexa data not written to file', 'red', attrs=['bold'])

    return 0
