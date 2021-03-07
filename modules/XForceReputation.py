#python imports
import sys
import os
import subprocess
import json
import simplejson
import requests
from requests.auth import HTTPBasicAuth
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Retrieves the reputation data for domains and IPs against the IBM X-Force Exchange database.
***END DESCRIPTION***
'''
def POE(POE):

    #Add your IBM X-Force API Key and Password inside the quotes on the lines below <--------------------------
    
    APIKey = ''
    APIPassword = ''

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    xf_malflag = ''
    response_dump = ''
    xf = ''

    if (POE.logging == True):
        newlogentry = 'Module: XForceReputation'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if (APIKey == ''):
        print (colored('\r\n[x] An IBM X-Force Exchange API Key has not been input.  Create an account and generate an API Key and then apply /opt/mirage/modules/XForceReputation.py', 'red', attrs=['bold']))
        newlogentry = 'Unable to execute XForce reputation module - API Key/Password value not input.  Please add one to /opt/mirage/modules/XForceReputation.py'
        LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
        return -1

    if (APIPassword == ''):
        print (colored('\r\n[x] An IBM X-Force Exchange API Key Password has not been input.  Create an account and generate an API Key and then apply to /opt/mirage/modules/XForceReputation.py', 'red', attrs=['bold']))
        newlogentry = 'Unable to execute XForce reputation module - API Key/Password value not input.  Please add one to /opt/mirage/modules/XForceReputation.py'
        LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
        return -1

    malware_flag = 0
    botnet_flag = 0
    output = POE.logdir + 'XForceReputation.json'

    FI = fileio()

    print ('\r\n[*] Running X-Force reputation against: ' + POE.target)

    if (POE.url == True):
        xf = 'https://api.xforce.ibmcloud.com/url/' + POE.target
    elif (POE.domain == True):
        xf = 'https://api.xforce.ibmcloud.com/url/' + POE.target
    elif (POE.ip == True):
        xf = 'https://api.xforce.ibmcloud.com/ipr/' + POE.target

    try:
        req = requests.get(xf, auth=HTTPBasicAuth(APIKey, APIPassword))      
        response_dump = json.loads(req.content.decode("UTF-8"))
    except requests.ConnectionError:
        print (colored('[x] Unable to connect to IBM X-Force\'s reputation site', 'red', attrs=['bold']))
        POE.csv_line += 'N/A,' 
        return -1

    if (req.status_code != 200):
        print (colored("[-] HTTP {} returned".format(req.status_code), 'yellow', attrs=['bold']))
        if (req.status_code == 404):
            print (colored('[-] Target not found in dataset...', 'yellow', attrs=['bold']))
        elif (req.status_code == 403):
            print (colored('[x] 403 Forbidden - something is wrong with the connection or credentials...', 'red', attrs=['bold']))
        POE.csv_line += 'N/A,'           
        return -1                        
   
    try:        
        FI.WriteLogFile(output, json.dumps(response_dump, indent=4, sort_keys=True))
        print (colored('[*] X-Force reputation data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if ((POE.logging == True) and (POE.nolinksummary == False)):
            newlogentry = 'X-Force reputation data has been generated to file here: <a href=\"' + output + '\"> XForce Reputation Output </a>'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)            
    except:
        print (colored('[x] Unable to write X-Force reputation data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write X-Force reputation data to file'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        return -1

    FI.ReadFile(output)

    if (POE.domain == True):
        try:
            print ('[*] Site Category: ' + str(response_dump['result']['categoryDescriptions']))
            if (POE.logging == True):
                newlogentry = 'Site Category: ' + str(response_dump['result']['categoryDescriptions'])
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        except:
            print (colored('[x] Unable to locate categoryDescriptions...', 'red', attrs=['bold']))
    if (POE.ip == True):
        try:
            print ('[*] Site Category: ' + str(response_dump['categoryDescriptions']))
            if (POE.logging == True):
                newlogentry = 'Site Category: ' + str(response_dump['categoryDescriptions'])
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        except:
            print (colored('[x] Unable to locate categoryDescriptions...', 'red', attrs=['bold']))

    for curl_data in FI.fileobject:
        if (POE.debug == True):
            print ('[DEBUG]: ' + curl_data)
        if (curl_data.find('This category lists IPs of malicious websites or malware hosting websites')!= -1):
            malware_flag = 1
            xf_malflag = 'Target has been flagged for malware'
            print (colored('[-] Target has been flagged for malware', 'red', attrs=['bold']))
            break
        elif (curl_data.find('Botnet Command and Control Server')!= -1):
            botnet_flag = 1
            xf_malflag = 'Botnet Command and Control Server'
            print (colored('[-] Target has been flagged as a Botnet C2 server', 'red', attrs=['bold']))
            break
        elif (curl_data.find('IPs known for botnet-member activity')!= -1):
            botnet_flag = 1
            xf_malflag = 'IPs known for botnet-member activity'
            print (colored('[-] Target is known for botnet-member activity', 'red', attrs=['bold']))
            break
        elif (curl_data.find('This IP was involved in spam sending activities')!= -1):
            malware_flag = 1
            xf_malflag = 'This IP was involved in spam sending activities'
            print (colored('[-] Target is known for spam sending activities', 'red', attrs=['bold']))
            break
            
    if (malware_flag == 1):
        POE.csv_line += 'Malware,'
        if (POE.logging == True):
            newlogentry = xf_malflag
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
    elif (botnet_flag == 1):
        POE.csv_line += 'Botnet,'
        if (POE.logging == True):
            newlogentry = xf_malflag
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
    else:
        if (POE.logging == True):
            newlogentry = 'Target has not been flagged for malware'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        POE.csv_line += 'False,'

    return 0
