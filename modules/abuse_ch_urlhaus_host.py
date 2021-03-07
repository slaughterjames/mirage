#python imports
import sys
import os
import time
import datetime
import subprocess
import json
from urllib import request, parse
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Retrieves the reputation data for domains against the URLHaus dataset.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    reputation_dump = ''
    reputation_output_data = ''
    urlhaus = ''

    if (POE.logging == True):
        newlogentry = 'Module: abuse_ch_urlhaus_host'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if (POE.domain == False):
        print (colored('\r\n[-] Unable to execute abuse.ch URLHaus Host - target must be a domain - skipping.', 'yellow', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute abuse.ch URLHaus Host - target must be a domain - skipping.'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1


    global json
    query_status = ''
    firstseen = ''
    url_count = ''
    urlhaus_reference = ''
    output = POE.logdir + 'URLHausHost.json'

    FI = fileio()
    
    print ('\r\n[*] Running abuse.ch URLHaus Host against: ' + POE.target)

    urlhaus = "https://urlhaus-api.abuse.ch/v1/host/" #API URL
    data = {'host': POE.target} #Our header params
    data = parse.urlencode(data).encode() #Encode for transit
    req =  request.Request(urlhaus, data=data) # This will make the method "POST"
    response = request.urlopen(req) # Execute
    j = json.load(response, cls=None) # Give us the results as JSON
    response_dump = json.dumps(j, sort_keys=True, indent=4) #Pretty-up the JSON into something readable

    if (POE.debug == True):
        print (response_dump)

    try:        
        FI.WriteLogFile(output, response_dump)
        print (colored('[*] URLHausHost data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if ((POE.logging == True) and (POE.nolinksummary == False)):
            newlogentry = 'URLHausHost data has been generated to file here: <a href=\"' + output + '\"> URLHaus Host Output </a>'           
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
    except:
        print (colored('[x] Unable to write URLHausHost data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write URLHausHost data to file'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    try:
        #Open the file we just downloaded
        print ('[-] Reading URLHaus file: ' + output.strip())

        with open(output.strip(), 'rb') as read_file:
            data = json.load(read_file)
        read_file.close()

        # Check what kind of results we have
        query_status = data["query_status"]
        if (query_status == 'ok'):
            firstseen = data["firstseen"]
            url_count = data["url_count"]
            urlhaus_reference = data["urlhaus_reference"]
            print ('[*] Host first seen: ' + firstseen)
            print ('[*] There are ' + url_count + ' URLs associated with this host...')
            print (colored('[*] URLHaus reference: ' + urlhaus_reference, 'green', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'Host first seen: ' + firstseen
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)  
                newlogentry = 'There are ' + url_count + ' URLs associated with this host...'
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
                newlogentry = 'URLHaus reference: ' + urlhaus_reference
                LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry) 
        elif (query_status == 'no_results'):
            print (colored('[-] No results available for host...', 'yellow', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'No results available for host...'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        else:
            print (colored('[x] An error has occurred...', 'red', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'An error has occurred...'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)     
    except Exception as e:
        print (colored('[x] Error: ' + str(e) + ' Terminating...', 'red', attrs=['bold']))
        return -1

    return 0
