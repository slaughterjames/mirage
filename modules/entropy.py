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
Uses ent to determine the randomness of a domain
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    ent_output_data = ''
    output = logdir + 'ent.txt'
    malware_flag = 0
    intLen = 0
    entropy_line = ''
    entropy = 0
    domain = ''

    if (target.domain == False):
        print colored('\r\n[-] Unable to execute entropy - target must be a domain - skipping.', 'yellow', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to execute entropy - target must be a domain - skipping.'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    FI = fileio()

    print '\r\n[*] Running entropy against: ' + target.target

    intLen = len(target.target)

    if (target.target[intLen-4]=='.'):
        domain = target.target[0:intLen-4]
    elif (target.target[intLen-5]=='.'):
        domain = target.target[0:intLen-5]
    elif (target.target[intLen-6]=='.'):
        domain = target.target[0:intLen-6] 
    else:
        print colored('[*] Unable to determine exact domain structure.  Using entire string...', 'green', attrs=['bold'])  
        domain = target.target

    intLen = 0

    subproc = subprocess.Popen('echo \"' + domain + '\" | ent', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for ent_data in subproc.stdout.readlines():
        intLen = len(ent_data)
        if (ent_data.find('Entropy =') != -1):
            entropy_line = ent_data[10:intLen-16] 
            entropy = float(entropy_line)
            if (entropy > 2.75):
                print colored('[*] Entropy of ' + entropy_line + ' has a higher degree of randomness', 'red', attrs=['bold'])
            else:
                print colored('[*] Entropy is ' + entropy_line, 'green', attrs=['bold'])
        if (debug == True):
            print '[DEBUG]: ' + ent_data 
        ent_output_data += ent_data 
 
    target.targetdomainentropy = entropy_line
    
    if (ent_output_data != ''):                           
        if (logging == True):
            if (entropy > 2.75):
                newlogentry = '<strong>Entropy of ' + entropy_line + ' has a higher degree of randomness</strong>'
                LOG.WriteLog(logdir, target.target, newlogentry)
            else:
                newlogentry = '<strong>Entropy is ' + entropy_line + '</strong>'
                LOG.WriteLog(logdir, target.target, newlogentry)          

    return 0
