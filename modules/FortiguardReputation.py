#python imports
import sys
import os
import re
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
Type: Info - Description: Retrieves the categorization data for domains and IPs against Fortiguard's database.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    bc_output_data = ''
    fortiguardcategory = ''

    if (POE.useragent != 'default'):
        fg_user_agent =  POE.useragent
    else:
        fg_user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"

    malware_flag = 0
    output = POE.logdir + 'FortiguardReputation.txt'

    FI = fileio()
    HTML = fileio()
    HTML_Output = POE.logdir + 'Fortiguard_Output.html'

    print '\r\n[*] Running Fortiguard reputation against: ' + POE.target

    try:
        request = urllib2.Request("https://fortiguard.com/webfilter?q=" + POE.target)
        request.add_header("User-Agent", fg_user_agent)
        request.add_header("Origin", "https://fortiguard.com")
        request.add_header("Referer", "https://fortiguard.com/webfilter")
        response = urllib2.urlopen(request)
        try:
            html_data = response.read()
            cat = re.findall('Category: (.*?)" />', html_data, re.DOTALL)
            fortiguardcategory = cat[0]
            fg_output_data = 'Fortiguard Site Review\r'
            fg_output_data += 'Target has been categorized by Fortiguard as: ' + fortiguardcategory + '\r'                 
            if (fortiguardcategory == 'Malicious Websites'):
                print colored('[-] Target has been categorized by Fortiguard as: ' + fortiguardcategory, 'red', attrs=['bold'])
            elif (fortiguardcategory == 'Illegal or Unethical'):
               print colored('[-] Target has been categorized by Fortiguard as: ' + fortiguardcategory, 'red', attrs=['bold'])           
            elif (fortiguardcategory == 'Pornography'):
               print colored('[-] Target has been categorized by Fortiguard as: ' + fortiguardcategory, 'red', attrs=['bold'])
            elif (fortiguardcategory == 'Newly Observed Domain'):
               print colored('[-] Target has been categorized by Fortiguard as: ' + fortiguardcategory, 'yellow', attrs=['bold'])
            elif (fortiguardcategory == 'Spam URLs'):
               print colored('[-] Target has been categorized by Fortiguard as: ' + fortiguardcategory, 'yellow', attrs=['bold'])
            else:        
               print colored('[*] Target has been categorized by Fortiguard as: ' + fortiguardcategory, 'green', attrs=['bold']) 

        except Exception as e:
            print colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold'])
            if (POE.logging == True):
                POE.csv_line += 'N/A,'  
            return -1

    except Exception as e:
        print colored('[x] Unable to connect to the Fortiguard reputation site: ' + str(e), 'red', attrs=['bold'])
        if (POE.logging == True):
            POE.csv_line += 'N/A,'
        return -1

    try:        
        FI.WriteLogFile(output, fg_output_data)
        print colored('[*] Fortiguard reputation data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'Fortiguard reputation data has been generated to file here: <a href=\"' + output + '\"> Fortiguard Reputation Output </a>'
            LOG.WriteLog(POE.logdir,POE.target, newlogentry)
            newlogentry = '<strong>|-----------------> Target has been categorized as: ' + fortiguardcategory + '</strong>'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
           
    except:
        print colored('[x] Unable to write Fortiguard reputation data to file', 'red', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'Unable to write Fortiguard reputation data to file'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
        return -1

    try:        

        HTML.WriteLogFile(HTML_Output, html_data)
        print colored('[*] Fortiguard HTML output data had been written to file here: ', 'green') + colored(HTML_Output, 'blue', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'Fortiguard HTML output data had been written to file here: <a href=\"' + HTML_Output + '\"> Fortiguard HTML Output </a>'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += fortiguardcategory.strip() + ','             

    except:
        print colored('[x] Unable to write Fortiguard output data to file', 'red', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'Unable to write Fortiguard output data to file'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
        return -1

    return 0
