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
Retrieves the categorization data for domains and IPs against Bluecoat's database.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    bc_output_data = ''
    response_dump = ''
    bc = 'http://sitereview.bluecoat.com/rest/categorization'

    if (target.useragent != ''):
        bc_user_agent =  target.useragent
    else:
        bc_user_agent = {"User-Agent": "Mozilla/5.0"}

    malware_flag = 0
    output = logdir + 'BCReputation.txt'

    FI = fileio()

    print '[*] Running BlueCoat reputation against: ' + target.target

    payload = {"url": target.target}

    try:
        req = requests.post(
            bc,
            data=payload)
      
        response_dump = json.loads(req.content.decode("UTF-8"))
        if (debug == True):
            print '[DEBUG]: ' + response_dump 
    except requests.ConnectionError:
        print colored('[x] Unable to connect to BlueCoat reputation site', 'red', attrs=['bold'])
 
    if (req.status_code != 200):
        print "[-] HTTP {} returned".format(req.status_code)

    else:
        target.bluecoatcategory = BeautifulSoup(response_dump["categorization"], "lxml").get_text()
        bc_output_data = 'Blue Coat Site Review\r'
        bc_output_data += 'Target has been categorized by BlueCoat as: ' + target.bluecoatcategory + '\r'
        bc_output_data += 'Rating date: ' + BeautifulSoup(response_dump["ratedate"], "lxml").get_text()[0:35]        
        if (target.bluecoatcategory == 'Malicious Outbound Data/Botnets'):
            target.bluecoat = True
            print colored('[-] Target has been categorized by BlueCoat as: ' + target.bluecoatcategory, 'red', attrs=['bold'])
        elif (target.bluecoatcategory == 'Malicious Sources/Malnets'):
            target.bluecoat = True
            print colored('[-] Target has been categorized by BlueCoat as: ' + target.bluecoatcategory, 'red', attrs=['bold'])
        elif (target.bluecoatcategory == 'Hacking'):
            target.bluecoat = True
            print colored('[-] Target has been categorized by BlueCoat as: ' + target.bluecoatcategory, 'red', attrs=['bold'])           
        elif (target.bluecoatcategory == 'Scam/Questionable/Illegal'):
            target.bluecoat = True
            print colored('[-] Target has been categorized by BlueCoat as: ' + target.bluecoatcategory, 'red', attrs=['bold'])
        elif (target.bluecoatcategory == 'Pornography'):
            target.bluecoat = True
            print colored('[-] Target has been categorized by BlueCoat as: ' + target.bluecoatcategory, 'red', attrs=['bold'])
        elif (target.bluecoatcategory == 'Child Pornography'):
            target.bluecoat = True
            print colored('[-] Target has been categorized by BlueCoat as: ' + target.bluecoatcategory, 'red', attrs=['bold'])
        elif (target.bluecoatcategory == 'Suspicious'):
            target.bluecoat = True
            print colored('[-] Target has been categorized by BlueCoat as: ' + target.bluecoatcategory, 'red', attrs=['bold'])
        else:
            target.BlueCoat = False         
            print colored('[*] Target has been categorized by BlueCoat as: ' + target.bluecoatcategory, 'green', attrs=['bold'])    
    try:        
        FI.WriteLogFile(output, bc_output_data)
        print colored('[*] BlueCoat reputation data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'BlueCoat reputation data has been generated to file here: <a href=\"' + output + '\"> BlueCoat Reputation Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
            newlogentry = '|-----------------> Target has been categorized as: ' + target.bluecoatcategory
            LOG.WriteLog(logdir, target.target, newlogentry)            
    except:
        print colored('[x] Unable to write BlueCoat reputation data to file', 'red', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Unable to write BlueCoat reputation data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
