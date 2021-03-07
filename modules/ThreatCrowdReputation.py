#python imports
import sys
import os
import subprocess
import json
import simplejson
import requests
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
    output = POE.logdir + 'ThreatCrowd.json'

    FI = fileio()

    if (POE.logging == True):
        newlogentry = 'Module: ThreatCrowdReputation'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    print ('\r\n[*] Running ThreatCrowd reputation against: ' + POE.target)

    try:
        if (POE.url == True):
            print (colored('[-] ThreatCrowd does not support URL query at this time.  Skipping... ' + POE.target, 'yellow', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'ThreatCrowd does not support URL query at this time. <strong>' + POE.target + '</strong>'
                LOG.WriteStrongSubLog(logdir, target.target, newlogentry)
                POE.csv_line += 'N/A,'
            return -1
        elif (POE.domain == True):
            tc = 'https://www.threatcrowd.org/searchApi/v2/domain/report/'
            data = requests.get(tc, {"domain":POE.target}).text
            json_data = json.loads(data)
        elif (POE.ip == True):
            tc = 'http://www.threatcrowd.org/searchApi/v2/ip/report/'
            data = requests.get(tc, {"ip":POE.target}).text
            json_data = json.loads(data)
        else:
            print (colored('[x] A target type error has occurred...', 'red', attrs=['bold']))
            if (logging == True):
                POE.csv_line += 'N/A,'
            return -1
    except Exception as e:
        print (colored('[x] Unable to connect to ThreatCrowd site: ' + str(e), 'red', attrs=['bold']))
        if (POE.logging == True):
            POE.csv_line += 'N/A,' 
        return -1 

    if (POE.debug == True):
        print (json_data)

    try:        
        FI.WriteLogFile(output, json.dumps(json_data, indent=4, sort_keys=True))
        print (colored('[*] ThreatCrowd data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if ((POE.logging == True) and (POE.nolinksummary == False)):
            newlogentry = 'ThreatCrowd data has been generated to file here: <a href=\"' + output + '\"> ThreatCrowd Output </a>'           
            LOG.WriteSummary(POE.logdir, POE.target, newlogentry)
    except:
        print (colored('[x] Unable to write ThreatCrowd data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write ThreatCrowd data to file'
            LOG.WriteSummary(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1


    try:
        # Check what kind of results we have
        query_status = json_data["response_code"]
        if (query_status == '1'):
            if ('hashes' in json_data):
                print (colored('[-] Malware hashes have been found associated with this target...', 'red', attrs=['bold']))
                if (POE.logging == True):
                    POE.csv_line += 'Malware,'
                    newlogentry = 'Malware hashes have been found associated with this target'
                    LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            elif ('subdomains' in json_data):
                print (colored('[-] Subdomains have been found associated with this target...', 'yellow', attrs=['bold'])) 
                if (POE.logging == True):
                    POE.csv_line += 'Subdomains,'
                    newlogentry = 'Subdomains have been found associated with this target'
                    LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            else: 
                print (colored('[-] Target has not been flagged for malware...', 'green', attrs=['bold']))
                if (POE.logging == True):
                    POE.csv_line += 'False,'
                    newlogentry = 'Target has not been flagged for malware'
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        else:
            print (colored('[-] No data has been found associated with this target...', 'green', attrs=['bold']))
            if (POE.logging == True):
                POE.csv_line += 'False,'
                newlogentry = 'No data has been found associated with this target...'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
    except Exception as e:
        print (colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold']))

    return 0
