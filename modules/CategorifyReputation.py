#python imports
import re
import requests
from bs4 import BeautifulSoup
from termcolor import colored

#third-party imports
from bs4 import BeautifulSoup

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Retrieves the categorization data for domains and IPs against Website Categorify's database.
***END DESCRIPTION***
'''

# Function to find the specific 'span' tag with text 'Category'
def is_category_title(tag):
    return tag.name == 'span' and tag.get('class', []) == ['title'] and tag.text.strip() == 'Category'


def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    request = ''
    headers = ''
    categorifycategory = ''

    if (POE.logging == True):
        newlogentry = 'Module: CategorifyReputation'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if (POE.useragent != 'default'):
        fg_user_agent =  POE.useragent
    else:
        fg_user_agent = "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

    print ('\r\n[*] Running CategorifyReputation against: ' + POE.target)

    try:
        request = 'https://categorify.org/?website=' + POE.target + '&try=Search'
        headers = headers = {
                      'User-Agent': fg_user_agent,
                  }
        response = requests.get(request, headers=headers)
        #response = requests.get(request)
        if (POE.debug == True):
            print (response.text)        
 
        try:
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            category_title_tag = soup.find(is_category_title)

            # Find the next sibling which is a 'span' (assuming it exists)
            if category_title_tag:
                category_tag = category_title_tag.find_next_sibling('span')
                categorifycategory = category_tag.text.strip() if category_tag else 'No category found'
            else:
                categorifycategory = 'Category title not found'


            print('[*] Target has been categorized by Categorify as: ' + categorifycategory)             
            if (POE.logging == True):
                newlogentry = 'Target has been categorized by Categorify as: ' + categorifycategory
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
        print (colored('[x] Unable to connect to the Categorify reputation site: ' + str(e), 'red', attrs=['bold']))
        if (POE.logging == True):
            POE.csv_line += 'N/A,'
            newlogentry = 'Unable to connect to the Categorify reputation site: ' + str(e)
            LOG.WriteStrongSubLog(POE.logdir,POE.target, newlogentry)
        return -1

    return 0