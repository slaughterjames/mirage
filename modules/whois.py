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
Type: Info - Description: Queries the WhoIs information for a target
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    whois_dump = ''
    whois_output_data = ''
    country = ''
    country_count = 0
    output = POE.logdir + 'WhoIs.txt'
    if  (POE.debug == True):
        print output     

    FI = fileio()

    print '\r\n[*] Running WhoIs against: ' + POE.target

    subproc = subprocess.Popen('whois ' + POE.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for whois_data in subproc.stdout.readlines():
         whois_output_data += whois_data
         if (whois_data.find('No match for \"')!= -1):
             print colored('[x] No WhoIs record available for this domain...', 'red', attrs=['bold'])
             POE.csv_line += 'N/A,'
             return -1 
         elif (whois_data.find('connect: Network is unreachable')!= -1):
             print colored('[x] WhoIs is unable to connect to the network [proxy blocked?] ', 'red', attrs=['bold'])
             POE.csv_line += 'N/A,'
             return -1  
         elif (country_count==0):
             if ((whois_data.find('country')!= -1) or (whois_data.find('Country')!= -1)):
                 country = whois_data
                 country_count += 1
             
         if  (POE.debug == True):
             print whois_data    

    try:        
        FI.WriteLogFile(output, whois_output_data)
        print colored('[*] Country Code: ', 'green', attrs=['bold']) + colored(country, 'blue', attrs=['bold'])
        print colored('[*] WhoIs data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'WhoIs file has been generated to file here: <a href=\"' + output + '\"> WhoIs Output </a>'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            newlogentry = '|-----------------> ' + country
            if (country==''):
                POE.csv_line += 'N/A,'
            else: 
                POE.csv_line += country.rstrip() + ','
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
    except:
        print colored('[x] Unable to write whois data to file', 'red', attrs=['bold']) 
        if (POE.logging == True):
            newlogentry = 'Unable to write whois data to file'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry) 
        return -1

    return 0
