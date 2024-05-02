#python imports
import json
import requests
from requests.auth import HTTPBasicAuth
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger


'''
***BEGIN DESCRIPTION***
Type: Info - Description: Retrieves the reputation data for domains and IPs against the urlscan.io database.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    response_dump = ''
    urlsio = ''

    if (POE.logging == True):
        newlogentry = 'Module: URLScanReport'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    output = POE.logdir + 'URLScanReport.json'

    print ('\r\n[*] Running URLScanReport against: ' + POE.target)

    urlsio = 'https://urlscan.io/api/v1/search/?q=' + POE.target
   

    try:
        req = requests.get(urlsio)      
        response_dump = json.loads(req.content.decode("UTF-8"))
    except requests.ConnectionError:
        print (colored('[x] Unable to connect to urlscan.io', 'red', attrs=['bold']))        
        return -1

    if (req.status_code != 200):
        print (colored("[-] HTTP {} returned".format(req.status_code), 'yellow', attrs=['bold']))
        if (req.status_code == 404):
            print (colored('[-] Target not found in dataset...', 'yellow', attrs=['bold']))
        elif (req.status_code == 403):
            print (colored('[x] 403 Forbidden - something is wrong with the connection or credentials...', 'red', attrs=['bold']))               
        return -1                        
   
    try:        
        with open(output,'w') as write_file:
            write_file.write(json.dumps(response_dump, indent=4, sort_keys=True))
        write_file.close()
        print (colored('[*] URLScanReport data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if ((POE.logging == True) and (POE.nolinksummary == False)):
            newlogentry = 'URLScanReport data has been generated to file here: <a href=\"' + output + '\"> URLScanReport Output </a>'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)            
    except:
        print (colored('[x] Unable to write URLScanReport data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write URLScanReport data to file'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        return -1

    return 0
