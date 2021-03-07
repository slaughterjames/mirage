#python imports
import sys
import os
import subprocess
from termcolor import colored

#third-party imports
import shodan

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Retrieves the available data for targets against the Shodan dataset.
***END DESCRIPTION***
'''
def POE(POE):

    #Add your Shodan API key inside the quotes on the line below <--------------------------
    apikey = ''

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''    
    shodan_dump = ''
    shodan_output_data = ''
    output = POE.logdir + 'Shodan.txt'
    if (POE.logging == True):
        newlogentry = 'Module: Shodan'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if (apikey == ''):
        print (colored('\r\n[x] Unable to execute Shodan module - apikey value not input.  Please add one to /opt/mirage/modules/Shodan.py', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute Shodan module - apikey value not input.  Please add one to /opt/mirage/modules/Shodan.py'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1
    else:
        api = shodan.Shodan(apikey)

    if (POE.ip == False):
        print (colored('\r\n[-] Unable to execute Shodan module - target must be an IP - skipping.', 'yellow', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute Shodan module - target must be an IP - skipping.'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    FI = fileio()           

    print ('\r\n[*] Running Shodan against: ' + POE.target)

    # Lookup the host
    host = api.host(POE.target)

    # Print general info
    shodan_dump = """IP: %s\r
    Organization: %s\r
    Operating System: %s\r
    """ % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))

    # Print all banners
    for item in host['data']:
        shodan_dump += """
        Port: %s
        Banner: %s
        """ % (item['port'], item['data'])
        print (str(item))
   
    try:        
        FI.WriteLogFile(output, shodan_dump)
        print (colored('[*] Shodan data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Shodan data has been generated to file here: <a href=\"' + output + '\"> Shodan Output </a>'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'True,'
    except:
        print (colored('[x] Unable to write Shodan data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write Shodan data to file'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'False,'
        return -1

    return 0
