#python imports
import sys
import os
import json
import simplejson
import requests
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Retrieves the reputation data for domains and IPs against the ThreatCrowd database.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    token = ''
    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    data = ''
    tc = ''
    output = logdir + 'ThreatCrowdReputation.txt'

    FI = fileio()

    print '[*] Running ThreatCrowd reputation against: ' + target.target

    if (target.url == True):
        print '[-] ThreatCrowd does not support URL query at this time.'

        if (logging == True):
            newlogentry = 'ThreatCrowd does not support URL query at this time. <strong>' + target.target + '</strong>'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1
    elif (target.domain == True):
        tc = 'https://www.threatcrowd.org/searchApi/v2/domain/report/'
        data = requests.get(tc, {"domain":target.target}).text
        if (debug == True):
           print '[DEBUG]: ' + data
    else:
        tc = 'http://www.threatcrowd.org/searchApi/v2/ip/report/'
        headers = {'ip': target.target}
        data = requests.get(tc, {"ip":target.target}).text
        if (debug == True):
           print '[DEBUG]: ' + data

    JSON = json.loads(data)
    if (debug == True):
        print '[DEBUG]: ' + json.dumps(JSON, indent=4, sort_keys=True)     
   
    try:        
        FI.WriteLogFile(output, json.dumps(JSON, indent=4, sort_keys=True))
        print colored('[*] ThreatCrowd reputation data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'ThreatCrowd reputation data has been generated to file here: <a href=\"' + output + '\"> ThreatCrowd Reputation Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
    except:
        print colored('[x] Unable to write ThreatCrowd reputation data to file', 'red', attrs=['bold'])  
        if (logging == True):
            newlogentry = 'Unable to write ThreatCrowd reputation data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
