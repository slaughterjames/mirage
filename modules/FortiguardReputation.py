#python imports
import re
import requests
from termcolor import colored

#third-party imports
from bs4 import BeautifulSoup

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Retrieves the categorization data for domains and IPs against FortiGuard's database.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    request = ''
    headers = ''
    fortiguardcategory = ''

    if (POE.logging == True):
        newlogentry = 'Module: FortiguardReputation'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if (POE.useragent != 'default'):
        fg_user_agent =  POE.useragent
    else:
        fg_user_agent = "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

    print ('\r\n[*] Running FortiGuard reputation against: ' + POE.target)

    try:
        request = "https://fortiguard.com/webfilter?q=" + POE.target
        headers = headers = {
                      'User-Agent': fg_user_agent,
                      'Origin': 'https://fortiguard.com',
                      'Referer': 'https://fortiguard.com/webfilter' 
                  }
        response = requests.get(request, headers=headers)
        if (POE.debug == True):
            print (response.text)        
 
        try:
            html_data = response.text
            cat = re.findall('Category: (.*?)" />', html_data, re.DOTALL)
            fortiguardcategory = cat[0]
            fg_output_data = 'FortiGuard Site Review\r'
            fg_output_data += 'Target has been categorized by FortiGuard as: ' + fortiguardcategory + '\r'                 
            if (fortiguardcategory == 'Malicious Websites'):
                print (colored('[-] Target has been categorized by FortiGuard as: ' + fortiguardcategory, 'red', attrs=['bold']))
            elif (fortiguardcategory == 'Illegal or Unethical'):
               print (colored('[-] Target has been categorized by FortiGuard as: ' + fortiguardcategory, 'red', attrs=['bold']))        
            elif (fortiguardcategory == 'Pornography'):
               print (colored('[-] Target has been categorized by FortiGuard as: ' + fortiguardcategory, 'red', attrs=['bold']))
            elif (fortiguardcategory == 'Newly Observed Domain'):
               print (colored('[-] Target has been categorized by FortiGuard as: ' + fortiguardcategory, 'yellow', attrs=['bold']))
            elif (fortiguardcategory == 'Spam URLs'):
               print (colored('[-] Target has been categorized by FortiGuard as: ' + fortiguardcategory, 'yellow', attrs=['bold']))
            else:        
               print (colored('[*] Target has been categorized by FortiGuard as: ' + fortiguardcategory, 'green', attrs=['bold']))

            if (POE.logging == True):
                newlogentry = 'Target has been categorized by FortiGuard as: ' + fortiguardcategory
                LOG.WriteStrongSubLog(POE.logdir,POE.target, newlogentry)
        except Exception as e:
            if (str(e) == 'list index out of range'):
                print (colored('[-] No results available for host...: ', 'yellow', attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'No data available...'
                    LOG.WriteStrongSubLog(POE.logdir,POE.target, newlogentry)
                    POE.csv_line += 'N/A,'             
            else:
                print (colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'An error has occurred: ' + str(e)
                    LOG.WriteStrongSubLog(POE.logdir,POE.target, newlogentry)
                    POE.csv_line += 'N/A,'  
            return -1
    except Exception as e:
        print (colored('[x] Unable to connect to the FortiGuard reputation site: ' + str(e), 'red', attrs=['bold']))
        if (POE.logging == True):
            POE.csv_line += 'N/A,'
            newlogentry = 'Unable to connect to the FortiGuard reputation site: ' + str(e)
            LOG.WriteStrongSubLog(POE.logdir,POE.target, newlogentry)
        return -1

    return 0