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
Retrieves the categorization data for domains and IPs against Bluecoat's database.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    bc_output_data = ''

    if (target.useragent != 'default'):
        bc_user_agent =  target.useragent
    else:
        bc_user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"

    malware_flag = 0
    output = logdir + 'BCReputation.txt'

    FI = fileio()
    JSO = fileio()
    JSON_Output = logdir + 'BC_JSON_Output.txt'

    print '\r\n[*] Running BlueCoat reputation against: ' + target.target

    try:
        data = json.dumps({'url':target.target,'captcha':''})
        request = urllib2.Request("https://sitereview.bluecoat.com/resource/lookup", data=data)
        request.add_header("User-Agent", bc_user_agent)
        request.add_header("Origin", "https://sitereview.bluecoat.com")
        request.add_header("Referer", "https://sitereview.bluecoat.com/lookup")
        request.add_header("X-Requested-With", "XMLHttpRequest")
        request.add_header("Content-Type", "application/json; charset=utf-8")
        response = urllib2.urlopen(request, data)
        try:
            json_data = json.loads(response.read())
            if json_data.has_key("errorType"):
                if json_data["errorType"] == "captcha":
                    print colored('[x] Bluecoat captcha has engaged, please complete it to resume... ' + str(e), 'red', attrs=['bold'])
                    return -1
            target.bluecoatcategory = BeautifulSoup(json_data["categorization"][0]["name"], "lxml").get_text()
            bc_output_data = 'Blue Coat Site Review\r'
            bc_output_data += 'Target has been categorized by BlueCoat as: ' + target.bluecoatcategory + '\r'
            bc_output_data += 'Rating date: ' + BeautifulSoup(json_data["rateDate"], "lxml").get_text()[0:35]        
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
            elif (target.bluecoatcategory == 'Uncategorized'):
               target.bluecoat = True
               print colored('[-] Target has been categorized by BlueCoat as: ' + target.bluecoatcategory, 'yellow', attrs=['bold'])
            else:
               target.BlueCoat = False         
               print colored('[*] Target has been categorized by BlueCoat as: ' + target.bluecoatcategory, 'green', attrs=['bold'])           
        except Exception as e:
            print colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold'])
            return -1

    except Exception as e:
        print colored('[x] Unable to connect to BlueCoat reputation site: ' + str(e), 'red', attrs=['bold'])
        return -1
   
    try:        
        FI.WriteLogFile(output, bc_output_data)
        print colored('[*] BlueCoat reputation data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'BlueCoat reputation data has been generated to file here: <a href=\"' + output + '\"> BlueCoat Reputation Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
            newlogentry = '<strong>|-----------------> Target has been categorized as: ' + target.bluecoatcategory + '</strong>'
            LOG.WriteLog(logdir, target.target, newlogentry)            
    except:
        print colored('[x] Unable to write BlueCoat reputation data to file', 'red', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Unable to write BlueCoat reputation data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    try:        

        JSO.WriteLogFile(JSON_Output, json.dumps(json_data, indent=4, sort_keys=True))
        print colored('[*] BlueCoat JSON output data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'BlueCoat JSON output data had been written to file here: <a href=\"' + JSON_Output + '\"> BlueCoat JSON Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)            

    except:
        print colored('[x] Unable to write JSON output data to file', 'red', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Unable to write JSON output data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
