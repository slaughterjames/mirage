#python imports
import subprocess
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Executes a grep against the current TorDNSEL list of exit nodes.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    tor_output_data = ''
    tor_data = ''

    if (POE.logging == True):
        newlogentry = 'Module: tor_node'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if ((POE.ip == False) and (POE.ipaddress == '')):
        print (colored('\r\n[-] Unable to execute ToR Node IP grep - an IP must be available as target or via active scanning - skipping...', 'yellow', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute ToR Node IP grep - an IP must be available as target or via active scanning - skipping...'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    if (not POE.ipaddress == ''):        
        print ('\r\n[*] Running ToR Node grep against: ' + POE.ipaddress)        
        subproc = subprocess.Popen('grep ' + POE.ipaddress + ' /opt/mirage/feeds/ToR_Exits.txt', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    else:            
        print ('\r\n[*] Running ToR Node grep against: ' + POE.target)     
        subproc = subprocess.Popen('grep ' + POE.target + ' /opt/mirage/feeds/ToR_Exits.txt', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for tor_data in subproc.stdout.readlines():
        if (POE.debug == True):
            print ('[DEBUG]: ' + str(tor_data))
        tor_output_data += str(tor_data)

    if (len(tor_output_data) == 0):
        print (colored('[-] Target does not appear to be a ToR exit node.', 'green', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Target does not appear to be a ToR exit node.'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)                       
    else:
        print (colored('[-] ToR: Target is or was a ToR exit node...', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'ToR: Target is or was a ToR exit node...'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)             
         
    return 0