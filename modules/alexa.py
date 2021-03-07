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
Type: Info - Description: Executes a grep against the top 1 million Internet domains on Alexa.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    alx_output_data = ''
    output = POE.logdir + 'Alexa.txt'

    if (POE.logging == True):
        newlogentry = 'Module: alexa'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if ((POE.ip == True) or (POE.url == True)):
        print (colored('\r\n[-] Unable to execute Alexa module - target must be a domain - skipping.', 'yellow', attrs=['bold']) )
        if (POE.logging == True):
            newlogentry = 'Unable to execute Alexa module - target must be a domain - skipping.'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1   

    FI = fileio()

    print ('\r\n[*] Running Alexa grep against: ' + POE.target)

    subproc = subprocess.Popen('grep ' + POE.target + ' /opt/mirage/feeds/top-1m.csv', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for alx_data in subproc.stdout.readlines():
        if (alx_data != ''):
            print (colored('[-] Target does appear in the Alexa rankings.', 'yellow', attrs=['bold']))
        if (POE.debug == True):
            print ('[DEBUG]: ' + alx_data)
        alx_output_data += alx_data 
    
    if (alx_output_data != ''):                      
        print (colored('[-] Target does appear in the Alexa rankings.', 'green', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Target does appear in the Alexa rankings.'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'True,'       
    else:
        print (colored('[-] Target does not appear in the Alexa rankings.  This could be a malicious indicator.', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Target does not appear in the Alexa rankings.  This could be a malicious indicator.'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)   
            POE.csv_line += 'False,' 

    return 0
