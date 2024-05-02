#python imports
import subprocess
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Executes a grep against the top 1 million Internet domains on Majestic Million.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    maj_output_data = ''

    if (POE.logging == True):
        newlogentry = 'Module: majestic'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if ((POE.ip == True) or (POE.url == True)):
        print (colored('\r\n[-] Unable to execute majestic module - target must be a domain - skipping.', 'yellow', attrs=['bold']) )
        if (POE.logging == True):
            newlogentry = 'Unable to execute majestic module - target must be a domain - skipping.'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1   

    print ('\r\n[*] Running Majestic Million grep against: ' + POE.target)

    subproc = subprocess.Popen('grep ' + POE.target + ' /opt/mirage/feeds/majestic_update.csv', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for maj_data in subproc.stdout.readlines():
        if (POE.debug == True):
            print ('[DEBUG]: ' + str(maj_data))
        maj_output_data += str(maj_data)

    if (len(maj_output_data) == 0):
        print (colored('[-] Target does not appear in the Majestic Million rankings.  This could be a malicious indicator..', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Target does not appear in the Majestic Million rankings.  This could be a malicious indicator.'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)                       
    else:
        print (colored('[-] Target does appear in the Majestic Million rankings.', 'green', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Target does appear in the Majestic Million rankings.'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)             

    return 0
