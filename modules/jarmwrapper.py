#python imports
import sys
import os
import subprocess
import time
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Active - Description: Fingerprints the site using Salesforce's Jarm 
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    jarm_data = ''
    jarm_output_data = ''

    if (POE.logging == True):
        newlogentry = 'Module: jarmwrapper'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    FI = fileio()
    

    output = POE.logdir + 'Jarm.txt'
    
    print ('\r\n[*] Running jarmwrapper against: ' + POE.target)

    subproc = subprocess.Popen('python3 /opt/jarm/jarm.py ' + POE.target + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

     
    print (colored('[*] Jarm data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
    if (POE.logging == True):
        newlogentry = 'Jarm file has been generated to file here: <a href=\"' + output + '\"> Jarm Output </a>'
        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)

    time.sleep(3)

    try:
        #Open the file we just downloaded
        print ('[-] Reading Jarm file: ' + output.strip())            
        FI.ReadFile(output.strip())
        #with open(output.strip(), 'r') as read_file:
        #    data = read_file.readlines()
        #read_file.close()
    except Exception as e:
        print (colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold']))
        return -1

    for jarm_data in FI.fileobject:
        jarm_output_data += str(jarm_data).strip('b\'\\n') + '\n'
        if (POE.debug == True):
            print (jarm_output_data)
        
        if('JARM: 00000000000000000000000000000000000000000000000000000000000000' in jarm_data):
            print (colored('[-] Resolved IP: IP failed to resolve.' + jarm_output_data, 'yellow',attrs=['bold']))
            if (POE.logging == True):
                newlogentry = jarm_output_data
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        elif ('JARM:' in jarm_data):
            print (colored('[*] ' + jarm_output_data, 'green',attrs=['bold']))
            if (POE.logging == True):
                newlogentry = jarm_output_data
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
   
    return 0
