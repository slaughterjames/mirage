#python imports
import sys
import os
import subprocess
from termcolor import colored

#third-party imports
from nslookup import Nslookup

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Passive - Description: Executes an NSLookup against the target.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    nsl_output_data = ''
    dns_query = ''
    soa_record = ''
    dns_record_all = ''
    output = POE.logdir + 'NSLookup.txt'

    FI = fileio()

    if (POE.logging == True):
        newlogentry = 'Module: pynslookup'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    print ('\r\n[*] Running pynsookup against: ' + POE.target)

    dns_query = Nslookup()

    soa_record = dns_query.soa_lookup(POE.target)
    nsl_output_data += 'SOA Record Full Response: ' + str(soa_record.response_full) + '\n\r'
    nsl_output_data += 'SOA Record Answer: ' + str(soa_record.answer) + '\n\r'
    if (POE.debug == True):
        print('[DEBUG] soa_record.response_full: ' + soa_record.response_full, soa_record.answer)
        print('[DEBUG] soa_record.answer: ' + soa_record.answer)

    dns_record_all = dns_query.dns_lookup_all(POE.target)
    nsl_output_data += 'Full DNS Record Response: ' + str(dns_record_all.response_full) + '\n\r'
    nsl_output_data += 'Full DNS Record Answer: ' + str(dns_record_all.answer) + '\n\r'
    if (POE.debug == True):
        print('[DEBUG] dns_record_all.response_full: ' + dns_record_all.response_full)
        print('[DEBUG] dns_record_all.answer: ' + dns_record_all.answer)
              
    try:       
        FI.WriteLogFile(output, nsl_output_data)
        print (colored('[*] NSLookup data has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'NSLookup data has been generated to file here: <a href=\"' + output + '\"> NSLookup Output </a>'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'True,'
    except:
        print (colored('[x] Unable to write NSLookup data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write NSLookup data to file'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'False,'
        return -1

    return 0
