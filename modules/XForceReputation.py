#python imports
import sys
import os
import subprocess
import json
import simplejson
import urllib
import urllib2
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

    #Add your IBM X-Force token key inside the quotes on the line below <--------------------------
    token = ''

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    curl_output_data = ''
    response_dump = ''
    xf = ''

    if (token == ''):
        print colored('[x] Unable to execute XForce reputation module - token value not input.  Please add one to /opt/mirage/modules/XForceReputation.py', 'red', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to execute XForce reputation module - token value not input.  Please add one to /opt/mirage/modules/XForceReputation.py'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1


    global json
    malware_flag = 0
    output = logdir + 'XForceReputation.txt'

    FI = fileio()

    if (token == ''):
        print colored('[x] An IBM X-Force Exchange Token has not been input.  Create an account and generate a token to use this module', 'red', attrs=['bold'])
        return 1

    print '[*] Running X-Force reputation against: ' + target.target

    if (target.url == True):
        xf = 'https://api.xforce.ibmcloud.com/url/' + target.target
    elif (target.domain == True):
        xf = 'https://api.xforce.ibmcloud.com/url/' + target.target
    else:
        xf = 'https://api.xforce.ibmcloud.com/ipr/' + target.target


    curl_cmd = 'curl -X GET --header \'Accept: application/json\' --header \'Authorization: Basic ' + token + '\' \'' + xf + '\''
    #print curl_cmd
    subproc = subprocess.Popen(curl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for curl_data in subproc.stdout.readlines():
        if (debug == True):
            print '[DEBUG]: ' + curl_data 
        if (curl_data.find('{\"Malware\":true}')!= -1):
            malware_flag = 1
            target.xforce = True
            print colored('[-] Target has been flagged for malware', 'red', attrs=['bold'])
        elif (curl_data.find('{\"Botnet Command and Control Server\":true}')!= -1):
            malware_flag = 1
            target.xforce = True
            print colored('[-] Target has been flagged as a Botnet C2 server', 'red', attrs=['bold'])
        curl_output_data += curl_data 
    #response_dump = json.dumps(json.JSONDecoder().decode(curl_output_data), sort_keys=True, indent = 4) 
    #print response_dump         
            
   
    try:        
        FI.WriteLogFile(output, curl_output_data)
        print colored('[*] X-Force reputation data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'X-Force reputation data has been generated to file here: <a href=\"' + output + '\"> XForce Reputation Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
            if (malware_flag == 1):
                newlogentry = '|-----------------> Target has been flagged for malware'
                LOG.WriteLog(logdir, target.target, newlogentry)            
    except:
        print colored('[x] Unable to write X-Force reputation data to file', 'red', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Unable to write X-Force reputation data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
