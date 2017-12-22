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
Queries the WhoIs information for a target
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    whois_dump = ''
    whois_output_data = ''
    country_count = 0
    output = logdir + 'WhoIs.txt'

    FI = fileio()

    print '\r\n[*] Running WhoIs against: ' + target.target

    subproc = subprocess.Popen('whois ' + target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for whois_data in subproc.stdout.readlines():
         whois_output_data += whois_data
         if (whois_data.find('connect: Network is unreachable')!= -1):
             print colored('[x] WhoIs is unable to connect to the network [proxy blocked?] ', 'red', attrs=['bold'])  
         elif (country_count==0):
             if ((whois_data.find('country')!= -1) or (whois_data.find('Country')!= -1)):
                 target.country = whois_data
                 country_count += 1
             
         if  (debug == True):
             print whois_data    

    try:        
        FI.WriteLogFile(output, whois_output_data)
        print colored('[*] Country Code: ', 'green', attrs=['bold']) + colored(target.country, 'blue', attrs=['bold'])
        print colored('[*] WhoIs data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'WhoIs file has been generated to file here: <a href=\"' + output + '\"> WhoIs Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
            newlogentry = '|-----------------> ' + target.country
            LOG.WriteLog(logdir, target.target, newlogentry)
    except:
        print colored('[x] Unable to write whois data to file', 'red', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to write whois data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
