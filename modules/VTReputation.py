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
Retrieves the reputation data for domains and IPs against the VirusTotal database.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    #Add your VirusTotal API key inside the quotes on the line below <--------------------------
    apikey = ''

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    reputation_dump = ''
    reputation_output_data = ''
    vt = ''

    if (apikey == ''):
        print colored('\r\n[x] Unable to execute VirusTotal reputation module - apikey value not input.  Please add one to /opt/mirage/modules/VTReputation.py', 'red', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to execute VirusTotal reputation module - apikey value not input.  Please add one to /opt/mirage/modules/VTReputation.py'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    global json
    malware_flag = 0
    output = logdir + 'VTReputation.txt'

    FI = fileio()
    
    print '\r\n[*] Running VT reputation against: ' + target.target

    if (target.url == True):
        vt = "https://www.virustotal.com/vtapi/v2/url/report"
        parameters = {"resource": target.target, "apikey": apikey.rstrip('\n')}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(vt, data)
        response = urllib2.urlopen(req)
        json = response.read()
        if (debug == True):
            print json
        response_dump = json.dumps(response)
    elif (target.domain == True):
        vt = "http://www.virustotal.com/vtapi/v2/domain/report"
        parameters = {"domain": target.target, "apikey": apikey.rstrip('\n')}
        response = urllib.urlopen('%s?%s' % (vt, urllib.urlencode(parameters))).read()
        response_dict = json.loads(response)
        if (debug == True):
           print response_dict
        response_dump = json.dumps(json.JSONDecoder().decode(response), sort_keys=True, indent = 4)
    else:
        vt = "http://www.virustotal.com/vtapi/v2/ip-address/report"
        parameters = {"ip": target.target, "apikey": apikey.rstrip('\n')}
        response = urllib.urlopen('%s?%s' % (vt, urllib.urlencode(parameters))).read()
        response_dict = json.loads(response)
        if (debug == True):
           print response_dict
        response_dump = json.dumps(json.JSONDecoder().decode(response), sort_keys=True, indent=4)

    if (response_dump.find('seen to host badware')!= -1):
        malware_flag = 1             
    elif (response_dump.find('known infection source')!= -1): 
        malware_flag = 1            

    if (malware_flag == 1):
        target.VT = True
        print colored('[-] Target has been flagged for malware', 'red', attrs=['bold'])  
    else:
        print colored('[*] Target has not been flagged for malware', 'green', attrs=['bold'])  
   
    try:        
        FI.WriteLogFile(output, response_dump)
        print colored('[*] VirusTotal reputation data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'VirusTotal data has been generated to file here: <a href=\"' + output + '\"> VirusTotal Reputation Output </a>'           
            LOG.WriteLog(logdir, target.target, newlogentry)
            if (malware_flag == 1):
                newlogentry = '<strong>|-----------------> Target has been flagged for malware</strong>'
                LOG.WriteLog(logdir, target.target, newlogentry)
    except:
        print colored('[x] Unable to write VirusTotal reputation data to file', 'red', attrs=['bold']) 
        if (logging == True):
            newlogentry = 'Unable to write VirusTotal reputation data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
