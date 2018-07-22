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
Retrieves the available data for targets against the Shodan dataset.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    #Add your Shodan API key inside the quotes on the line below <--------------------------
    apikey = ''

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''    
    shodan_dump = ''
    shodan_output_data = ''
    vt = ''

    if (apikey == ''):
        print colored('\r\n[x] Unable to execute Shodan module - apikey value not input.  Please add one to /opt/mirage/modules/Shodan.py', 'red', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to execute Shodan module - apikey value not input.  Please add one to /opt/mirage/modules/Shodan.py'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1
    else:
        api = shodan.Shodan(apikey)

    output = logdir + 'Shodan.txt'

    FI = fileio()       
    
    if (target.ip == False):
        print colored('\r\n[x] Unable to execute Shodan module - target must be an IP - skipping.', 'red', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to execute Shodan module - target must be an IP - skipping.'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    print '\r\n[*] Running Shodan against: ' + target.target

    # Lookup the host
    host = api.host(target.target)

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
   
    try:        
        FI.WriteLogFile(output, shodan_dump)
        print colored('[*] Shodan data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Shodan data has been generated to file here: <a href=\"' + output + '\"> Shodan Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
    except:
        print colored('[x] Unable to write Shodan data to file', 'red', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to write Shodan data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
