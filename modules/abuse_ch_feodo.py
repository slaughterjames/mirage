#python imports
import subprocess
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Executes a grep against the abuse.ch Feodo IP blocklist feed.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    feodo_output_data = ''
    feodo_data = ''

    if (POE.logging == True):
        newlogentry = 'Module: abuse_ch_feodo'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if ((POE.ip == False) and (POE.ipaddress == '')):
        print (colored('\r\n[-] Unable to execute abuse.ch Feodo IP grep - an IP must be available as target or via active scanning - skipping...', 'yellow', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute abuse.ch Feodo IP grep - an IP must be available as target or via active scanning - skipping...'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1
    
    if (not POE.ipaddress == ''):        
        print ('\r\n[*] Running abuse.ch Feodo grep against: ' + POE.ipaddress)
        subproc = subprocess.Popen('grep ' + POE.ipaddress + ' /opt/mirage/feeds/ipblocklist_aggressive.txt', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)      
    else:            
        print ('\r\n[*] Running abuse.ch Feodo grep against: ' + POE.target)        
        subproc = subprocess.Popen('grep ' + POE.target + ' /opt/mirage/feeds/ipblocklist_aggressive.txt', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for feodo_data in subproc.stdout.readlines():
        if (POE.debug == True):
            print ('[DEBUG]: ' + str(feodo_data))
        feodo_output_data += str(feodo_data)

    if (len(feodo_output_data) == 0):
        print (colored('[-] Target does not appear in the abuse.ch Feodo feed.', 'yellow', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Target does not appear in the abuse.ch Feodo feed.'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)                      
    else:
        print (colored('[-] Target appears in the abuse.ch Feodo feed.', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Target appears in the abuse.ch Feodo feed'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)    

    return 0
