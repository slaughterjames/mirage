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
Retrieves the reputation data for domains and IPs against the IBM X-Force Exchange database.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    #Add your IBM X-Force API Key and Password inside the quotes on the lines below <--------------------------
    
    APIKey = ''
    APIPassword = ''

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    xf_malflag = ''
    response_dump = ''
    xf = ''

    if (APIKey == ''):
        print colored('\r\n[x] An IBM X-Force Exchange API Key has not been input.  Create an account and generate an API Key and then apply /opt/mirage/modules/XForceReputation.py', 'red', attrs=['bold'])
        newlogentry = 'Unable to execute XForce reputation module - API Key/Password value not input.  Please add one to /opt/mirage/modules/XForceReputation.py'
        LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    if (APIPassword == ''):
        print colored('\r\n[x] An IBM X-Force Exchange API Key Password has not been input.  Create an account and generate an API Key and then apply to /opt/mirage/modules/XForceReputation.py', 'red', attrs=['bold'])
        newlogentry = 'Unable to execute XForce reputation module - API Key/Password value not input.  Please add one to /opt/mirage/modules/XForceReputation.py'
        LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    malware_flag = 0
    output = logdir + 'XForceReputation.txt'

    FI = fileio()

    print '\r\n[*] Running X-Force reputation against: ' + target.target

    if (target.url == True):
        xf = 'https://api.xforce.ibmcloud.com/url/' + target.target
    elif (target.domain == True):
        xf = 'https://api.xforce.ibmcloud.com/url/' + target.target
    elif (target.ip == True):
        xf = 'https://api.xforce.ibmcloud.com/ipr/' + target.target

    try:
        req = requests.get(xf, auth=HTTPBasicAuth(APIKey, APIPassword))
      
        response_dump = json.loads(req.content.decode("UTF-8"))
    except requests.ConnectionError:
        print colored('[x] Unable to connect to IBM X-Force\'s reputation site', 'red', attrs=['bold']) 

    if (req.status_code != 200):
        print colored("[-] HTTP {} returned".format(req.status_code), 'yellow', attrs=['bold'])
        if (req.status_code == 404):
            print colored('[-] Target not found in dataset...', 'yellow', attrs=['bold'])
        elif (req.status_code == 403):
            print colored('[x] 403 Forbidden - something is wrong with the connection or credentials...', 'red', attrs=['bold'])
        return -1                        
   
    try:        
        FI.WriteLogFile(output, json.dumps(response_dump, indent=4, sort_keys=True))
        print colored('[*] X-Force reputation data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'X-Force reputation data has been generated to file here: <a href=\"' + output + '\"> XForce Reputation Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)            
    except:
        print colored('[x] Unable to write X-Force reputation data to file', 'red', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Unable to write X-Force reputation data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    FI.ReadFile(output)

    for curl_data in FI.fileobject:
        if (debug == True):
            print '[DEBUG]: ' + curl_data 
        if (curl_data.find('{\"Malware\":true}')!= -1):
            malware_flag = 1
            xf_malflag = 'Malware'
            target.xforce = True
            print colored('[-] Target has been flagged for malware', 'red', attrs=['bold'])
            break
        elif (curl_data.find('Botnet Command and Control Server')!= -1):
            malware_flag = 1
            xf_malflag = 'Botnet Command and Control Server'
            target.xforce = True
            print colored('[-] Target has been flagged as a Botnet C2 server', 'red', attrs=['bold'])
            break
        elif (curl_data.find('IPs known for botnet-member activity')!= -1):
            malware_flag = 1
            xf_malflag = 'IPs known for botnet-member activity'
            target.xforce = True
            print colored('[-] Target is known for botnet-member activity', 'red', attrs=['bold'])
            break
        elif (curl_data.find('This IP was involved in spam sending activities')!= -1):
            malware_flag = 1
            xf_malflag = 'This IP was involved in spam sending activities'
            target.xforce = True
            print colored('[-] Target is known for spam sending activities', 'red', attrs=['bold'])
            break
            
    if (malware_flag == 1):
        newlogentry = '<strong>|-----------------> ' + xf_malflag + '</strong>'
        LOG.WriteLog(logdir, target.target, newlogentry)

    return 0
