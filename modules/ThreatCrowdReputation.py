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
Type: Info - Description: Retrieves the reputation data for domains and IPs against the ThreatCrowd database.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    
    data = ''
    tc = ''  
    malware_flag = 0
    subdomains_flag = 0

    JSO = fileio()
    JSON_Output = POE.logdir + 'TC_JSON_Output.json'

    print '\r\n[*] Running ThreatCrowd reputation against: ' + POE.target

    try:
        if (POE.url == True):
            print colored('[-] ThreatCrowd does not support URL query at this time.  Skipping... ' + POE.target, 'yellow', attrs=['bold'])
            if (logging == True):
                newlogentry = 'ThreatCrowd does not support URL query at this time. <strong>' + POE.target + '</strong>'
                LOG.WriteLog(logdir, target.target, newlogentry)
                POE.csv_line += 'N/A,'
            return -1
        elif (POE.domain == True):
            tc = 'https://www.threatcrowd.org/searchApi/v2/domain/report/'
            data = requests.get(tc, {"domain":POE.target}).text
        elif (POE.ip == True):
            tc = 'http://www.threatcrowd.org/searchApi/v2/ip/report/'
            data = requests.get(tc, {"ip":POE.target}).text
        else:
            print colored('[x] A target type error has occurred...', 'red', attrs=['bold'])
            if (logging == True):
                POE.csv_line += 'N/A,'
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
                        subdomains_flag = 1
                except Exception as e:
                    print colored('[-] No subdomains have been found associated with this target...', 'yellow', attrs=['bold'])                  
        except Exception as e:
            print colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold'])
            print colored('[*] Attempting to dump JSON output anyway...', 'green', attrs=['bold'])

    except Exception as e:
        print colored('[x] Unable to connect to ThreatCrowd site: ' + str(e), 'red', attrs=['bold'])
        if (POE.logging == True):
            POE.csv_line += 'N/A,' 
        return -1   

    try:        

        JSO.WriteLogFile(JSON_Output, json.dumps(json_data, indent=4, sort_keys=True))
        print colored('[*] ThreatCrowd JSON output data had been written to file here: ', 'green') + colored(JSON_Output, 'blue', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'ThreatCrowd JSON output data had been written to file here: <a href=\"' + JSON_Output + '\"> ThreatCrowd JSON Output </a>'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            if ((malware_flag == 1) and (subdomains_flag == 1)):
                newlogentry = '<strong>|-----------------> Malware hashes and subdomains have been found associated with this target...</strong>'
                POE.csv_line += 'Malware/Subdomains,'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            elif ((malware_flag == 1) and (subdomains_flag == 0)):
                newlogentry = '<strong>|-----------------> Malware hashes have been found associated with this target...</strong>'
                POE.csv_line += 'Malware,'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            elif ((malware_flag == 0) and (subdomains_flag == 1)):
                newlogentry = '<strong>|-----------------> Subdomains have been found associated with this target...</strong>'
                POE.csv_line += 'Subdomains,'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry) 
            else:
                if (POE.logging == True):
                    POE.csv_line += 'True,'
                                     
 
    except Exception as e:
        print colored('[x] Unable to write JSON output data to file' + str(e), 'red', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Unable to write JSON output data to file'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
        return -1

    return 0
