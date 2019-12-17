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
Type: Info - Description: Retrieves information from URLScan.io's database.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    urlscan_output_data = ''
    urlscan_category = ''

    if (POE.useragent != 'default'):
        urlscan_user_agent =  POE.useragent
    else:
        urlscan_user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"

    malware_flag = 0
    output = POE.logdir + 'URLScanioReputation.txt'

    FI = fileio()
    JSO = fileio()
    JSON_Output = POE.logdir + 'URLScanio_JSON_Output.json'

    print '\r\n[*] Running URLScan.io data against: ' + POE.target

    try:
        request = urllib2.Request("https://urlscan.io/api/v1/search/?q=" + POE.target)
        request.add_header("User-Agent", urlscan_user_agent)
        response = urllib2.urlopen(request)
        try:
            json_data = json.loads(response.read())
            if not json_data.get("results"):
                print colored('[x] Search results unavailable for this domain... ', 'red', attrs=['bold'])
                print colored('[x] URLScan data not written to file.', 'red', attrs=['bold'])
                POE.csv_line += 'False,'
                return -1
            else:
                POE.csv_line += 'True,'
                #try:
                    #    if  "description" in json_data["category"]:
                    #        urlscan_category = BeautifulSoup(json_data["category"]["description"], "lxml").get_text()

                    #    else:
                    #        taloscategory = 'N/A'
                    #except Exception as e:
                    #    taloscategory = 'N/A'
                    #    print colored('[x] Something\'s gone wrong with the JSON... ', 'red', attrs=['bold'])
                    #    POE.csv_line += 'N/A,'
                    #    return -1 
                #if json_data.has_key("category"):
                    #try:
                    #    if  "description" in json_data["category"]:
                    #        urlscan_category = BeautifulSoup(json_data["category"]["description"], "lxml").get_text()
                    #    else:
                    #        taloscategory = 'N/A'
                    #except Exception as e:
                    #    taloscategory = 'N/A'
                    #    print colored('[x] Something\'s gone wrong with the JSON... ', 'red', attrs=['bold'])
                    #    POE.csv_line += 'N/A,'
                    #    return -1 
                #else: 
                #    taloscategory = 'N/A'

                #urlscan_output_data = 'URLScan Output Data\r'
                #urlscan_output_data += 'Target has been categorized by Cisco Talos as: ' + taloscategory + '\r'  
                #if (taloscategory.strip() == 'Malware'):
                #    print colored('[-] Target has been categorized by Cisco Talos as: ' + taloscategory, 'red', attrs=['bold'])
                #elif (taloscategory.strip() == 'Pornography'):
                #    print colored('[-] Target has been categorized by Cisco Talos as: ' + taloscategory, 'red', attrs=['bold'])
                #else:                
                #    if (taloscategory.strip() == 'N/A'):  
                #        print colored('[*] Target has been categorized by Cisco Talos as: ' + taloscategory, 'yellow', attrs=['bold'])
                #    else:
                #        print colored('[*] Target has been categorized by Cisco Talos as: ' + taloscategory, 'green', attrs=['bold'])  
        except Exception as e:
            print colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold'])
            print colored('[*] Attempting to dump JSON output anyway...', 'green', attrs=['bold'])
            return -1

    except Exception as e:
        print colored('[x] Unable to connect to the urlscan.io site: ' + str(e), 'red', attrs=['bold'])
        #POE.csv_line += 'N/A,'
        return -1

    try:        
        JSO.WriteLogFile(JSON_Output, json.dumps(json_data, indent=4, sort_keys=True))
        print colored('[*] UrlScan JSON output data had been written to file here: ', 'green') + colored(JSON_Output, 'blue', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'URLScan JSON output data had been written to file here: <a href=\"' + JSON_Output + '\"> URLScan JSON Output </a>'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)            

    except:
        print colored('[x] Unable to write JSON output data to file', 'red', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'Unable to write JSON output data to file'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
        return -1

    return 0
