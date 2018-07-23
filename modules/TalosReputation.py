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
Retrieves the categorization data for domains and IPs against Cisco's Talos database.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    talos_output_data = ''

    if (target.useragent != 'default'):
        talos_user_agent =  target.useragent
    else:
        talos_user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"

    malware_flag = 0
    output = logdir + 'TalosReputation.txt'

    FI = fileio()
    JSO = fileio()
    JSON_Output = logdir + 'Talos_JSON_Output.txt'

    print '\r\n[*] Running Talos reputation against: ' + target.target

    try:
        request = urllib2.Request("https://talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fdomain%2F&query_entry=" + target.target + "&offset=0&order=ip+asc")
        request.add_header("User-Agent", talos_user_agent)
        request.add_header("Referer", "https://www.talosintelligence.com/reputation_center/lookup?search=" + target.target)
        response = urllib2.urlopen(request)
        try:
            json_data = json.loads(response.read())
            if json_data.has_key("error"):
                print colored('[x] Search results unavailable for this domain... ' + target.taloscategory, 'red', attrs=['bold'])
            else:
                if json_data.has_key("category"):
                    try:
                        if  "description" in json_data["category"]:
                            target.taloscategory = BeautifulSoup(json_data["category"]["description"], "lxml").get_text()
                        else:
                            target.taloscategory = 'N/A'
                    except Exception as e:
                        target.taloscategory = 'N/A'
                else: 
                    target.taloscategory = 'N/A'
                talos_output_data = 'Cisco Talos Site Review\r'
                talos_output_data += 'Target has been categorized by Cisco Talos as: ' + target.taloscategory + '\r'  
                if (target.taloscategory == 'Malware'):
                    target.talos = True
                    print colored('[-] Target has been categorized by Cisco Talos as: ' + target.taloscategory, 'red', attrs=['bold']) 
                elif (target.taloscategory == 'Pornography'):
                    target.talos = True
                    print colored('[-] Target has been categorized by Cisco Talos as: ' + target.taloscategory, 'red', attrs=['bold'])
                else:
                    target.talos = False  
                    if (target.taloscategory.strip() == 'N/A'):  
                        print colored('[*] Target has been categorized by Cisco Talos as: ' + target.taloscategory, 'yellow', attrs=['bold'])
                    else:
                        print colored('[*] Target has been categorized by Cisco Talos as: ' + target.taloscategory, 'green', attrs=['bold'])  
        except Exception as e:
            print colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold'])
            print colored('[*] Attempting to dump JSON output anyway...', 'green', attrs=['bold'])

    except Exception as e:
        print colored('[x] Unable to connect to the Talos reputation site: ' + str(e), 'red', attrs=['bold'])
        return -1

    try:        
        FI.WriteLogFile(output, talos_output_data)
        print colored('[*] Cisco Talos reputation data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Cisco Talos reputation data has been generated to file here: <a href=\"' + output + '\"> Cisco Talos Reputation Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
            newlogentry = '<strong>|-----------------> Target has been categorized as: ' + target.bluecoatcategory + '</strong>'
            LOG.WriteLog(logdir, target.target, newlogentry)            
    except:
        print colored('[x] Unable to write Cisco Talos reputation data to file', 'red', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Unable to write Cisco Talos reputation data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    try:        
        JSO.WriteLogFile(JSON_Output, json.dumps(json_data, indent=4, sort_keys=True))
        print colored('[*] Cisco Talos JSON output data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Cisco Talos JSON output data had been written to file here: <a href=\"' + JSON_Output + '\"> Cisco Talos JSON Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)            

    except:
        print colored('[x] Unable to write JSON output data to file', 'red', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Unable to write JSON output data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
