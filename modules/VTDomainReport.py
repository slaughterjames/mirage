#python imports
import json
from vtapi3 import VirusTotalAPIDomains, VirusTotalAPIError
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Retrieves the reputation data for domains against the VirusTotal database.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    whois = ''

    if (POE.logging == True):
        newlogentry = 'Module: VTDomainReport'
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if (POE.domain == False):
        print (colored('\r\n[-] Unable to execute VTDomainReport - target must be a domain - skipping.', 'yellow', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute VTDomainReport - target must be a domain - skipping.'
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
        print (colored('\r\n[x] Unable to execute VTDomainReport - apikey value not input.  Please add one to Please add one to /opt/static/static.conf', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute VTDomainReport - apikey value not input.  Please add one to Please add one to /opt/static/static.conf'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    global json
    malware_flag = 0
    badware_flag = 0
    botnet_flag = 0
    infection_flag = 0
    output = POE.logdir + 'VTDomainReport.json'
    output_whois = POE.logdir + 'VTDomainReport_whois.txt'
    vtwhois_data = ''
    vtwhois_output_data = ''
    
    print ('\r\n[*] Running VTDomainReport against: ' + POE.target)

    vt_api_domains = VirusTotalAPIDomains(apikey)

    try:
        result = vt_api_domains.get_report(POE.target)
    except VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if (vt_api_domains.get_last_http_error() == vt_api_domains.HTTP_OK):
            result = json.loads(result)
            result = json.dumps(result, sort_keys=False, indent=4)
            if (POE.debug==True):
                print(result)
        else:
            print('HTTP Error [' + str(vt_api_domains.get_last_http_error()) +']')

    if (result.find('seen to host badware')!= -1):
        malware_flag = 1             
    elif (result.find('known infection source')!= -1): 
        malware_flag = 1
    elif (result.find('bot networks')!= -1): 
        botnet_flag = 1
    elif (result.find('malware repository, spyware and malware')!= -1): 
        malware_flag = 1 

    if (malware_flag == 1):
        POE.VT = True
        print (colored('[-] Target has been flagged for malware', 'red', attrs=['bold']))
    elif (botnet_flag == 1):
        POE.VT = True
        print (colored('[-] Target has been flagged as a botnet source', 'red', attrs=['bold']))
    else:
        print (colored('[*] Target has not been flagged for malware', 'green', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Target has not been flagged for malware'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
   
    try:        
        with open(output,'w') as write_file:
            write_file.write(result)
        write_file.close()
        print (colored('[*] VirusTotal domain report data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if (POE.logging == True):
            if (POE.nolinksummary == False):
                newlogentry = 'VirusTotal domain report data has been generated to file here: <a href=\"' + output + '\"> VirusTotal Domain Report </a>'           
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            if ((malware_flag == 1) and (badware_flag == 1) and (infection_flag == 1) and (botnet_flag == 1)):
                newlogentry = 'Target has been flagged for malware, has been seen to host badware, is a known infection source and is a botnet source'
                POE.csv_line += 'Malware/Subdomains/Infection_Source/Botnet_Source,'
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            elif ((malware_flag == 1) and (badware_flag == 1) and (infection_flag == 0) and (botnet_flag == 1)):
                newlogentry = 'Target has been flagged for malware, has been seen to host badware and is a botnet source'
                POE.csv_line += 'Malware/Badware,'
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            elif ((malware_flag == 1) and (badware_flag == 0) and (infection_flag == 1) and (botnet_flag == 1)):
                newlogentry = 'Target has been flagged for malware and is a known infection source and is a botnet source'
                POE.csv_line += 'Malware/Infection_Source,'
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            elif ((malware_flag == 1) and (badware_flag == 0) and (infection_flag == 0) and (botnet_flag == 0)):
                newlogentry = 'Target has been flagged for malware and is a botnet source'
                POE.csv_line += 'Malware,'
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            elif ((malware_flag == 0) and (badware_flag == 1) and (infection_flag == 0) and (botnet_flag == 0)):
                newlogentry = 'Target has been seen to host badware'
                POE.csv_line += 'Badware,'
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            elif ((malware_flag == 0) and (badware_flag == 0) and (infection_flag == 1) and (botnet_flag == 0)):
                newlogentry = 'Target is a known infection source'
                POE.csv_line += 'Infection_Source,'
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            elif ((malware_flag == 0) and (badware_flag == 0) and (infection_flag == 0) and (botnet_flag == 1)):
                newlogentry = 'Target is a known botnet source'
                POE.csv_line += 'Botnet_Source,'
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            else:
                POE.csv_line += 'False,'
    except:
        print (colored('[x] Unable to write VirusTotal domain report data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write VirusTotal domain report data to file'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    try:
        result = json.loads(result)
        whois=result['data']['attributes']['whois']
        if (POE.debug==True):
            print (whois)
        
        with open(output_whois,'w') as write_file:
            write_file.write(whois)
        write_file.close()
        print (colored('[*] VirusTotal Domain WhoIs data had been written to file here: ', 'green') + colored(output_whois, 'blue', attrs=['bold']))
        if ((POE.logging == True) and (POE.nolinksummary == False)):
            newlogentry = 'VirusTotal Domain WhoIs data has been generated to file here: <a href=\"' + output_whois + '\"> VirusTotal Domain WhoIs Data </a>'           
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
    except:
        print (colored('[x] Unable to write VirusTotal Domain WhoIs data to file', 'red', attrs=['bold']))
        return -1

    try:
        #Open the file we just downloaded
        print ('[-] Reading VirusTotal Domain WhoIs file: ' + output_whois.strip())

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