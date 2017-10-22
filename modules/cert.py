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
Pulls the target's certificate data using OpenSSL
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    cert_data = ''
    cert_output_data = ''

    FI = fileio()

    if not target.https_data:
        print colored('[-] No ports were found hosting an HTTPs application.', 'red', attrs=['bold'])
        return -1 

    for port in target.https_data:

        output = logdir + 'Cert_port_' + str(port) + '.txt'
    
        print '[*] Running cert against: ' + target.target

        subproc = subprocess.Popen('openssl s_client -showcerts -connect ' + target.target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for cert_data in subproc.stdout.readlines():
            cert_output_data += cert_data
            if  (debug == True):
                print cert_data    

        try:        
            FI.WriteLogFile(output, cert_output_data)
            print colored('[*] Cert data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
            if (logging == True):
                newlogentry = 'Cert file has been generated to file here: <a href=\"' + output + '\"> Cert Output </a>'
                LOG.WriteLog(logdir, target.target, newlogentry)
        except:
            print colored('[x] Unable to write cert data to file', 'red', attrs=['bold'])  
            if (logging == True):
                newlogentry = 'Unable to cert strings data to file'
                LOG.WriteLog(logdir, target.target, newlogentry)
            return -1

    return 0
