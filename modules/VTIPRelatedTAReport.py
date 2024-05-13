#python imports
import json
import datetime
import requests
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Retrieves any threat actors associated to an IP from the VirusTotal database.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''    

    if (POE.logging == True):
        newlogentry = 'Module: VTIPRelatedTAReport'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if ((POE.ip == False) and (POE.ipaddress == '')):
        print (colored('\r\n[-] Unable to execute VTIPRelatedTAReport - an IP must be available as target or via active scanning - skipping...', 'yellow', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute VTIPRelatedTAReport - an IP must be available as target or via active scanning - skipping...'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1
    
    for apikeys in POE.apikeys: 
        for key, value in apikeys.items():
            if (POE.debug == True):
                print ('[DEBUG] API: ' + str(key) + ' | API Key: ' + str(value))
            if (key == 'virustotal'):
                print ('\r\n[*] API key located!')
                apikey = value     

    if (apikey == ''):
        print (colored('\r\n[x] Unable to execute VTIPRelatedTAReport - apikey value not input.  Please add one to /opt/static/static.conf', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute VTIPRelatedTAReport - apikey value not input.  Please add one to /opt/static/static.conf'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    total = 0
    ta = ''
    source_region = ''
    vt = "https://www.virustotal.com/api/v3/ip_addresses/"
    output = POE.logdir + 'VTIPRelatedTAReport.json'

    headers = {"x-apikey": apikey}    

    try:
        if (not POE.ipaddress == ''):
            print ('\r\n[*] Running VTIPRelatedTAReport against: ' + POE.ipaddress)
            response = requests.get(vt + POE.ipaddress + '/related_threat_actors', headers=headers)

        else:            
            print ('\r\n[*] Running VTIPRelatedTAReport against: ' + POE.target)        
            response = requests.get(vt + POE.target + '/related_threat_actors', headers=headers)       
    except Exception as err:
        print(str(err))
    else:        
        if (response.status_code == 200):            
            result = json.loads(response.text)
            result = json.dumps(result, sort_keys=False, indent=4)
            if (POE.debug==True):
                print(result)
            try:        
                with open(output,'w') as write_file:
                    write_file.write(result)
                write_file.close()                
                print (colored('[*] VirusTotal IP related threat actors report data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
                if (POE.logging == True):
                    if (POE.nolinksummary == False):  
                        newlogentry = 'VirusTotal IP related threat actors report data has been generated to file here: <a href=\"' + output + '\"> VirusTotal IP Related Threat Actors </a>'           
                        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            except:
                print (colored('[x] Unable to write VirusTotal IP Related Threat Actors report data to file', 'red', attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'Unable to write VirusTotal IP Related Threat Actors report data to file'
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
                    POE.csv_line += 'N/A,'
                return -1
        
            result = json.loads(result)
            total = result['meta']['count']

            print ('[-] Number of threat actors associated with this IP: ' + str(total))
            newlogentry = 'Number of threat actors associated with this IP: ' + str(total)
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)

            if (total > 0):
                ta = result['data'][0]['attributes']['name']
                print ('[-] Threat actor name: ' + ta)
                newlogentry = 'Threat actor name: ' + ta
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)                
                source_region = result['data'][0]['attributes']['source_region']
                print ('[-] Threat actor source region: ' + source_region)
                newlogentry = 'Threat actor source region: ' + source_region
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)                 
        else:
            print('HTTP Error [' + str(response.status_code) +']')

    return 0