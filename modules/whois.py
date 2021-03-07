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
    registrar = ''
    registrar_count = 0
    output = POE.logdir + 'WhoIs.txt'
    if  (POE.debug == True):
        print (output)

    FI = fileio()

    if (POE.logging == True):
        newlogentry = 'Module: whois'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    print ('\r\n[*] Running WhoIs against: ' + POE.target)

    subproc = subprocess.Popen('whois ' + POE.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for whois_data in subproc.stdout.readlines():
         whois_output_data += str(whois_data).strip('b\'\\n') + '\n'
         if (b'No match for' in whois_data):                  
             print (colored('[x] No WhoIs record available for this domain...', 'red', attrs=['bold']))
             POE.csv_line += 'N/A,'
             if (POE.logging == True):
                 newlogentry = 'No WhoIs record available for this domain...'
                 LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
             return -1
         if (b'connect: Network is unreachable' in whois_data):         
             print (colored('[x] WhoIs is unable to connect to the network [proxy blocked?] ', 'red', attrs=['bold']))
             POE.csv_line += 'N/A,'
             if (POE.logging == True):
                 newlogentry = 'WhoIs is unable to connect to the network [proxy blocked?]'
                 LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
             return -1  
         if (country_count == 0):
             if (b'country' in whois_data) or (b'Country' in whois_data):
                 country = str(whois_data).strip('b\'\\n')
                 country_count += 1
         if (registrar_count == 0):
             if (b'registrar:' in whois_data) or (b'Registrar:' in whois_data):
                 registrar = str(whois_data).strip('b\'\\n')
                 registrar_count += 1
             
         if  (POE.debug == True):
             print (whois_data)

    if (country == ''):
        country = 'Country: N/A'

    try:        
        FI.WriteLogFile(output, whois_output_data)
        print (colored('[*] ', 'green', attrs=['bold']) + colored(country.strip(), 'blue', attrs=['bold']))
        print (colored('[*] ', 'green', attrs=['bold']) + colored(registrar.strip(), 'blue', attrs=['bold']))
        print (colored('[*] WhoIs data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if (POE.logging == True):
            if (POE.nolinksummary == False):
                newlogentry = 'WhoIs data has been written to file here: <a href=\"' + output + '\"> WhoIs Output </a>'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            newlogentry = country
            if (country==''):
                POE.csv_line += 'N/A,'
            else: 
                POE.csv_line += country.rstrip() + ','
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            newlogentry = registrar
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)  
    except:
        print (colored('[x] Unable to write whois data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write whois data to file'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry) 
        return -1

    return 0
