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
Executes a grep against the abuse.ch Feodo IP blocklist feed.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    alx_output_data = ''
    output = logdir + 'Abuse_ch_feodo.txt'
    malware_flag = 0

    if (target.ip == False):
        print colored('\r\n[-] Unable to execute abuse.ch Feodo IP grep - target must be an IP - skipping.', 'yellow', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to execute abuse.ch Feodo IP grep - target must be an IP - skipping.'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    FI = fileio()

    print '\r\n[*] Running abuse.ch Feodo grep against: ' + target.target

    subproc = subprocess.Popen('grep ' + target.target + ' /opt/mirage/feeds/feodo_ipblocklist.txt', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for alx_data in subproc.stdout.readlines():
        if (alx_data != ''):
            target.abuse_ch_feodo = True
            malware_flag = 1
            print colored('[-] Target appears in the abuse.ch Feodo feed', 'red', attrs=['bold'])
        if (debug == True):
            print '[DEBUG]: ' + alx_data 
        alx_output_data += alx_data 
    
    if (alx_output_data != ''):                      
        if (malware_flag == 1):
            newlogentry = '<strong>abuse.ch: Target appears in the abuse.ch Feodo feed</strong>'
            LOG.WriteLog(logdir, target.target, newlogentry)
    else:
        print colored('[-] Target does not appear in the abuse.ch Feodo feed', 'yellow', attrs=['bold'])    
        print colored('[x] abuse.ch Feodo data not written to file', 'red', attrs=['bold'])

    return 0
