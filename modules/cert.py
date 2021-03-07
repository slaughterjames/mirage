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

    if (POE.logging == True):
        newlogentry = 'Module: cert'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if not POE.https_data:
        print (colored('\r\n[-] Cert - Active scan not undertaken for HTTPs ports.  Defaulting to 443...', 'yellow', attrs=['bold']))
        https_data = [443]
    else:
        https_data = POE.https_data 

    FI = fileio()

    for port in https_data:

        output = POE.logdir + 'Cert_port_' + str(port) + '.txt'
    
        print ('\r\n[*] Running cert against: ' + POE.target)

        subproc = subprocess.Popen('timeout 20s openssl s_client -showcerts -connect ' + POE.target + ':' + str(port) + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for cert_data in subproc.stdout.readlines():
            cert_output_data += str(cert_data).strip('b\'\\n') + 'n'
            if (POE.debug == True):
                print (cert_data)

        if (os.path.getsize(output) == 0):
            print (colored('[x] There was an error capturing cert data to file.', 'red', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'Unable to cert strings data to file'
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
                POE.csv_line += 'False,'                
            return -1
        else:            
            print (colored('[*] Cert data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'Cert file has been generated to file here: <a href=\"' + output + '\"> Cert Output </a>'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
                POE.csv_line += 'True,'

    return 0
