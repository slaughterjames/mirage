#python imports
import json
import datetime
from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Retrieves the reputation data for IPs against the VirusTotal database.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    whois = ''

    if (POE.logging == True):
        newlogentry = 'Module: VTIPReport'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if ((POE.ip == False) and (POE.ipaddress == '')):
        print (colored('\r\n[-] Unable to execute VTIPReport - an IP must be available as target or via active scanning - skipping...', 'yellow', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute VTIPReport - an IP must be available as target or via active scanning - skipping...'
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
        print (colored('\r\n[x] Unable to execute VTIPReport - apikey value not input.  Please add one to /opt/static/static.conf', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute VTIPReport - apikey value not input.  Please add one to /opt/static/static.conf'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    harmless = 0
    undetected = 0
    suspicious = 0
    malicious = 0
    last_modification_date = ''
    last_analysis_date = ''
    output = POE.logdir + 'VTIPReport.json'
    output_whois = POE.logdir + 'VTIPReport_whois.txt'
    vtwhois_data = ''
    vtwhois_output_data = ''
    
    vt_api_ip_addresses = VirusTotalAPIIPAddresses(apikey)

    try:
        if (not POE.ipaddress == ''):
            print ('\r\n[*] Running VTIPReport against: ' + POE.ipaddress)
            result = vt_api_ip_addresses.get_report(POE.ipaddress)           
        else:            
            print ('\r\n[*] Running VTIPReport against: ' + POE.target)        
            result = vt_api_ip_addresses.get_report(POE.target)        
    except VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if (vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK):
            result = json.loads(result)
            result = json.dumps(result, sort_keys=False, indent=4)
            if (POE.debug==True):
                print(result)
            try:        
                with open(output,'w') as write_file:
                    write_file.write(result)
                write_file.close()
                print ('[*] If a VirusTotal record exists, it will be located here: https://www.virustotal.com/gui/ip-address/' + str(POE.ipaddress))
                print (colored('[*] VirusTotal IP report data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'If a VirusTotal record exists, it will be located here: <a href=\"https://www.virustotal.com/gui/ip-address/' + str(POE.ipaddress) + '\"> VirusTotal Analysis </a>'
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
                    if (POE.nolinksummary == False):  
                        newlogentry = 'VirusTotal IP report data has been generated to file here: <a href=\"' + output + '\"> VirusTotal IP Report </a>'           
                        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            except:
                print (colored('[x] Unable to write VirusTotal IP report data to file', 'red', attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'Unable to write VirusTotal IP report data to file'
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
                    POE.csv_line += 'N/A,'
                return -1
        
            result = json.loads(result)
            harmless = result['data']['attributes']['last_analysis_stats']['harmless']
            undetected = result['data']['attributes']['last_analysis_stats']['undetected']
            suspicious  = result['data']['attributes']['last_analysis_stats']['suspicious']
            malicious = result['data']['attributes']['last_analysis_stats']['malicious']
            last_modification_date = result['data']['attributes']['last_modification_date']
            last_analysis_date = result['data']['attributes']['last_analysis_date']
            print ('[*] VirusTotal last modification date: ' + datetime.datetime.fromtimestamp(last_modification_date).strftime('%c'))
            newlogentry = 'VirusTotal last modification date: ' + datetime.datetime.fromtimestamp(last_modification_date).strftime('%c')
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            print ('[*] VirusTotal last analysis date: ' + datetime.datetime.fromtimestamp(last_analysis_date).strftime('%c'))
            newlogentry = 'VirusTotal last analysis date: ' + datetime.datetime.fromtimestamp(last_analysis_date).strftime('%c')
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)                         
            print (colored('[*] VirusTotal engine results: ', 'green', attrs=['bold']))
            print ('[-] Number of engines marking IP as harmless: ' + str(harmless))
            newlogentry = 'Number of engines marking IP as harmless: ' + str(harmless)
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            print ('[-] Number of engines not detecting IP: ' + str(undetected))
            newlogentry = 'Number of engines not detecting IP: ' + str(undetected)
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            print ('[-] Number of engines marking IP as suspicious: ' + str(suspicious))
            newlogentry = 'Number of engines marking IP as suspicious: ' + str(suspicious)
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            print ('[-] Number of engines marking IP as malicious: ' + str(malicious))
            newlogentry = 'Number of engines marking IP as malicious: ' + str(malicious)
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)            
        else:
            print('HTTP Error [' + str(vt_api_ip_addresses.get_last_http_error()) +']')
   
    try:        
        whois=result['data']['attributes']['whois']
        if (POE.debug==True):
            print (whois)
        
        with open(output_whois,'w') as write_file:
            write_file.write(whois)
        write_file.close()
        print (colored('[*] VirusTotal IP WhoIs data had been written to file here: ', 'green') + colored(output_whois, 'blue', attrs=['bold']))
        if ((POE.logging == True) and (POE.nolinksummary == False)):
            newlogentry = 'VirusTotal IP WhoIs data has been generated to file here: <a href=\"' + output_whois + '\"> VirusTotal IP WhoIs Data </a>'           
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
    except:
        print (colored('[x] Unable to write VirusTotal IP WhoIs data to file', 'red', attrs=['bold']))
        return -1

    try:
        #Open the file we just downloaded
        print ('[-] Reading VirusTotal IP WhoIs file: ' + output_whois.strip())

        with open(output_whois.strip(), 'r') as read_file:
            data = read_file.readlines()
        read_file.close()
    except Exception as e:
        print (colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold']))
        return -1

    for vtwhois_data in data:
        vtwhois_output_data += str(vtwhois_data).strip('b\'\\n') + '\n'
        if (POE.debug == True):
            print (vtwhois_output_data)

        if (('Create date:' in vtwhois_data) or ('Create Date:' in vtwhois_data) or ('create date:' in vtwhois_data) or ('Created Date:' in vtwhois_data) or ('created date:' in vtwhois_data)):
            print (colored('[*] ', 'green',attrs=['bold']) + colored(vtwhois_data.strip(), 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = vtwhois_data
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)

        if (('Update date:' in vtwhois_data) or ('Update Date:' in vtwhois_data) or ('update date:' in vtwhois_data) or ('Updated:' in vtwhois_data) or ('updated:' in vtwhois_data)):
            print (colored('[*] ', 'green',attrs=['bold']) + colored(vtwhois_data.strip(), 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = vtwhois_data
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        
        if (('Registrant Country:' in vtwhois_data) or ('Registrant country:' in vtwhois_data)or ('registrant country:' in vtwhois_data)):
            print (colored('[*] ', 'green',attrs=['bold']) + colored(vtwhois_data.strip(), 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = vtwhois_data
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)

        if ('Registrar:' in vtwhois_data):
            print (colored('[*] ', 'green',attrs=['bold']) + colored(vtwhois_data.strip(), 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = vtwhois_data
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)

    return 0
