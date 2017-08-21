#python imports
import sys
import os
import subprocess
from array import *
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Executes a full NMap session against the target.  ***Warning*** This may be seen to be somewhat invasive.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    nmap_data = ''
    nmap_output_data = ''
    https_data = array('i')
    cert_data = ''
    cert_output_data = ''
    nmap_output = logdir + 'NMap.txt'
    cert_output = logdir + 'Cert.txt'

    FI = fileio()
    
    print '[*] Running NMap against: ' + target.target

    subproc = subprocess.Popen('nmap -v -A -sV ' + target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for nmap_data in subproc.stdout.readlines():
         nmap_output_data += nmap_data
         if (nmap_data.find('ssl/http') != -1):
             intFromVal1 = nmap_data.find('/')
             if ((intFromVal1 != -1) and (intFromVal1 <7)):
                 tmpport = nmap_data[0:intFromVal1]
                 https_data.append(int(tmpport))
         if  (debug == True):
             print nmap_data    

    try:        
        FI.WriteLogFile(nmap_output, nmap_output_data)
        print colored('[*] NMap data had been written to file here: ', 'green') + colored(nmap_output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'NMap file has been generated to file here: <a href=\"' + nmap_output + '\"> NMap Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
    except:
        print colored('[x] Unable to write nmap data to file', 'red', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to write nmap data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    for port in https_data:

        print '[*] Running cert against: ' + target.target + ' port ' + str(port)

        if (logging == True):
            newlogentry = 'Running cert against: <strong>' + target.target + ' port ' + str(port) + '</strong>'
            LOG.WriteLog(logdir, target.target, newlogentry)

        subproc = subprocess.Popen('openssl s_client -showcerts -connect ' + target.target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for cert_data in subproc.stdout.readlines():
            cert_output_data += cert_data
            if (debug == True):
                print cert_data    

        try:        
            FI.WriteLogFile(cert_output, cert_output_data)
            print colored('[*] Cert data had been written to file here: ', 'green') + colored(cert_output, 'blue', attrs=['bold'])
            if (logging == True):
                newlogentry = 'Cert file has been generated to file here: <a href=\"' + cert_output + '\"> Cert Output </a>'
                LOG.WriteLog(logdir, target.target, newlogentry)
        except:
            print colored('[x] Unable to write cert data to file', 'red', attrs=['bold']) 
            if (logging == True):
                newlogentry = '[x] Unable to cert strings data to file'
                LOG.WriteLog(logdir, target.target, newlogentry)
            return -1

    return 0
