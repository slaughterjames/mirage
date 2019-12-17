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
Type: Active - Description: Pulls the target's certificate data using OpenSSL
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    cert_data = ''
    cert_output_data = ''
    https_data = []

    if not POE.https_data:
        print colored('\r\n[-] Cert - Active scan not undertaken for HTTPs ports.  Defaulting to 443...', 'yellow', attrs=['bold'])
        https_data = [443]
    else:
        https_data = POE.https_data 

    FI = fileio()

    for port in https_data:

        output = POE.logdir + 'Cert_port_' + str(port) + '.txt'
    
        print '\r\n[*] Running cert against: ' + POE.target

        subproc = subprocess.Popen('timeout 20s openssl s_client -showcerts -connect ' + POE.target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for cert_data in subproc.stdout.readlines():
            cert_output_data += cert_data
            if  (POE.debug == True):
                print cert_data    

        try:        
            FI.WriteLogFile(output, cert_output_data)
            print colored('[*] Cert data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
            if (POE.logging == True):
                newlogentry = 'Cert file has been generated to file here: <a href=\"' + output + '\"> Cert Output </a>'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
                POE.csv_line += 'True,'
                
        except:
            print colored('[x] Unable to write cert data to file', 'red', attrs=['bold'])  
            if (POE.logging == True):
                newlogentry = 'Unable to cert strings data to file'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
                POE.csv_line += 'False,'                
            return -1

    return 0
