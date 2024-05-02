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

'''
***BEGIN DESCRIPTION***
Type: Active - Description: Fingerprints the site using Salesforce's Jarm 
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    data = ''
    port = 0
    jarm_data = ['']

    if (POE.logging == True):
        newlogentry = 'Module: jarmwrapper'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)
  
    output = POE.logdir + 'Jarm_'
    if (POE.debug == True):
        print ('[DEBUG] Output: ' + output)

    if (len(POE.https_data) > 0):
        for port in POE.https_data:    
            print ('\r\n[*] Running jarmwrapper against: ' + POE.target + ':' + str(port))
            subproc = subprocess.Popen('python3 /opt/jarm/jarm.py ' + POE.target + ' -p ' + str(port) + ' -o ' + output + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            print (colored('[*] Jarm data had been updated to file here: ', 'green', attrs=['bold']) + colored(output + str(port) + '.csv', 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'Jarm data had been updated to file here: <a href=\"' + output + str(port) + '.csv' + '\"> Jarm Output </a>'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)              
            
            print ('[-] Sleeping for 5 seconds...')
            time.sleep(5)

            try: 
                with open(output + str(port) + '.csv', 'r') as read_file:
                    data = read_file.readlines()
            except Exception as e:
                print (colored('[x] Unable to open Jarm file ' + output + str(port) + ': ' + str(e), 'red',attrs=['bold']))
                break
            
            try:
                jarm_data = data[0].split(',')
            except Exception as e:
                 print (colored('[x] Jarmwrapper unable to continue: ' + str(e), 'red',attrs=['bold']))
                 return -1

            if (POE.debug == True):
                print (data)
                print ('[DEBUG] jarm_data[2]: ' + jarm_data[2])

            if('00000000000000000000000000000000000000000000000000000000000000' in jarm_data[2]):
                print (colored('[-] IP failed to resolve. JARM: ' + jarm_data[2], 'yellow',attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'IP failed to resolve. JARM: ' + jarm_data[2]
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            elif (jarm_data[2] == ''):
                    print (colored('[-] Matching Jarm output was not found...', 'yellow',attrs=['bold']))
                    if (POE.logging == True):
                        newlogentry = 'Matching Jarm output was not found...'
                        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            else:                
                    print (colored('[*] JARM: ' + jarm_data[2], 'green',attrs=['bold']))
                    if (POE.logging == True):
                        newlogentry = 'JARM: ' + jarm_data[2]
                        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)                    
    else:
        print ('\r\n[*] Running jarmwrapper against: ' + POE.target)
        subproc = subprocess.Popen('python3 /opt/jarm/jarm.py ' + POE.target + ' -o ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        print (colored('[*] Jarm data had been updated to file here: ', 'green', attrs=['bold']) + colored(output + '.csv', 'blue', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Jarm data had been updated to file here: <a href=\"' + output + str(port) + '.csv' + '\"> Jarm Output </a>'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)        
     
        print ('[-] Sleeping for 5 seconds...')
        time.sleep(5)

        try: 
            with open(output + '.csv', 'r') as read_file:
                data = read_file.readlines()
        except Exception as e:
            print (colored('[x] Unable to open Jarm file ' + output + ': ' + str(e), 'red',attrs=['bold']))
            return -1
                    
        try:
            jarm_data = data[0].split(',')
        except Exception as e:
            print (colored('[x] Jarmwrapper unable to continue: ' + str(e), 'red',attrs=['bold']))
            return -1

        if (POE.debug == True):
            print (data)
            print ('[DEBUG] jarm_data[2]: ' + jarm_data[2])

        if('00000000000000000000000000000000000000000000000000000000000000' in jarm_data[2]):
            print (colored('[-] IP failed to resolve. JARM: ' + jarm_data[2], 'yellow',attrs=['bold']))
            if (POE.logging == True):
                newlogentry = jarm_data[2]
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        elif (jarm_data[2] == ''):
                print (colored('[-] Matching Jarm output was not found...', 'yellow',attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'Matching Jarm output was not found...'
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        else:                
                print (colored('[*] JARM: ' + jarm_data[2], 'green',attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'JARM: ' + jarm_data[2]
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)            
            
    return 0
