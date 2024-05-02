#python imports
import json
from termcolor import colored

#third-party imports
import shodan

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Retrieves the available data for targets against the Shodan dataset.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''    
    output = POE.logdir + 'Shodan.json'
    if (POE.logging == True):
        newlogentry = 'Module: Shodan'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    for apikeys in POE.apikeys: 
        for key, value in apikeys.items():
            if (POE.debug == True):
                print ('[DEBUG] API: ' + str(key) + ' | API Key: ' + str(value))
            if (key == 'shodan'):
                print ('\r\n[*] API key located!')
                apikey = value         

    if (apikey == ''):
        print (colored('\r\n[x] Unable to execute Shodan module - apikey value not input.  Please add one to /opt/static/static.conf', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute Shodan module - apikey value not input.  Please add one to /opt/static/static.conf'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1
    else:
        api = shodan.Shodan(apikey)

    if ((POE.ip == False) and (POE.ipaddress == '')):
        print (colored('\r\n[-] Unable to execute Shodan module - an IP must be available as target or via active scanning - skipping...', 'yellow', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute Shodan module - an IP must be available as target or via active scanning - skipping...'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1         
    
    # Lookup the host
    if (not POE.ipaddress == ''):
        host = api.host(POE.ipaddress)
        print ('\r\n[*] Running Shodan against: ' + POE.ipaddress)
    else:
        host = api.host(POE.target)
        print ('\r\n[*] Running Shodan against: ' + POE.target)

    result = json.dumps(host, sort_keys=False, indent=4)

    if  (POE.debug == True):
        print (str(result))
   
    try:        
        with open(output,'w') as write_file:
            write_file.write(result)
        write_file.close()
        print (colored('[*] Shodan data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Shodan data has been generated to file here: <a href=\"' + output + '\"> Shodan Output </a>'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'True,'
    except Exception as e:
        print (colored('[x] Unable to write Shodan data to file...' + str(e), 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write Shodan data to file'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'False,'
        return -1
     
    print ('')

    result = json.loads(result)

    # Print general info
    print ('[-] Organisation: ' + host.get('org', 'n/a'))
    if (POE.logging == True):
        newlogentry = 'Organisation: ' + host.get('org', 'n/a')
        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)    
    print ('[-] Operating System: ' + str(host.get('os', 'n/a')))
    if (POE.logging == True):
        newlogentry = 'Operating System: ' + str(host.get('os', 'n/a'))
        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)     
    print ('[-] Country Code: ' + str(host.get('country_code', 'n/a')))
    if (POE.logging == True):
        newlogentry = 'Country Code: ' + str(host.get('country_code', 'n/a'))
        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)     
    print ('[-] RegionCode: ' + str(host.get('region_code', 'n/a')))
    if (POE.logging == True):
        newlogentry = 'RegionCode: ' + str(host.get('region_code', 'n/a'))
        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)    
    print ('[-] ASN: ' + str(host.get('asn', 'n/a')))
    if (POE.logging == True):
        newlogentry = 'ASN: ' + str(host.get('asn', 'n/a'))
        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)     
    for item in result['data']:
        print ('[-] Port: ' + str(item['port']))
        print ('[-] Banner: ' + str(item['data']))
   
    return 0