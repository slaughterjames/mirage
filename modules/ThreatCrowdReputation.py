#python imports
import sys
import os
import subprocess
import json
import simplejson
import requests
import urllib2
import urllib
from termcolor import colored

#third-party imports
from bs4 import BeautifulSoup

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Retrieves the reputation data for domains and IPs against the ThreatCrowd database.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    
    data = ''
    tc = ''  
    malware_flag = 0

    JSO = fileio()
    JSON_Output = logdir + 'TC_JSON_Output.txt'

    print '\r\n[*] Running ThreatCrowd reputation against: ' + target.target

    try:
        if (target.url == True):
            print colored('[-] ThreatCrowd does not support URL query at this time.  Skipping... ' + target.bluecoatcategory, 'yellow', attrs=['bold'])
            if (logging == True):
                newlogentry = 'ThreatCrowd does not support URL query at this time. <strong>' + target.target + '</strong>'
                LOG.WriteLog(logdir, target.target, newlogentry)
            return -1
        elif (target.domain == True):
            tc = 'https://www.threatcrowd.org/searchApi/v2/domain/report/'
            data = requests.get(tc, {"domain":target.target}).text
        elif (target.ip == True):
            tc = 'http://www.threatcrowd.org/searchApi/v2/ip/report/'
            data = requests.get(tc, {"ip":target.target}).text
        else:
            print colored('[x] A target type error has occurred...', 'red', attrs=['bold'])
            return -1

        try:
            json_data = json.loads(data)
            if json_data.has_key("hashes"):
                try:
                    if BeautifulSoup(json_data["hashes"][0], "lxml").get_text():
                        print colored('[-] Malware hashes have been found associated with this target...', 'red', attrs=['bold'])
                        malware_flag = 1
                except Exception as e:
                    print colored('[-] No malware hashes have been found associated with this target...', 'yellow', attrs=['bold'])
            if json_data.has_key("subdomains"):
                try:
                    if BeautifulSoup(json_data["subdomains"][0], "lxml").get_text():
                        print colored('[-] Subdomains have been found associated with this target...', 'red', attrs=['bold'])
                except Exception as e:
                    print colored('[-] No subdomains have been found associated with this target...', 'yellow', attrs=['bold'])                  
        except Exception as e:
            print colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold'])
            print colored('[*] Attempting to dump JSON output anyway...', 'green', attrs=['bold'])

    except Exception as e:
        print colored('[x] Unable to connect to ThreatCrowd site: ' + str(e), 'red', attrs=['bold'])
        return -1   

    try:        

        JSO.WriteLogFile(JSON_Output, json.dumps(json_data, indent=4, sort_keys=True))
        print colored('[*] ThreatCrowd JSON output data had been written to file here: ', 'green') + colored(JSON_Output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'ThreatCrowd JSON output data had been written to file here: <a href=\"' + JSON_Output + '\"> ThreatCrowd JSON Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)   
            if (malware_flag == 1):
                newlogentry = '<strong>|-----------------> Malware hashes have been found associated with this target...</strong>'
                LOG.WriteLog(logdir, target.target, newlogentry)                     

    except Exception as e:
        print colored('[x] Unable to write JSON output data to file' + str(e), 'red', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Unable to write JSON output data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
