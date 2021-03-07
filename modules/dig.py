#python imports
import sys
import os
import subprocess
import pydig
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Passive - Description: Executes Dig against the target.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    dig_output_data = ''
    output = POE.logdir + 'Dig.txt'

    FI = fileio()

    if (POE.logging == True):
        newlogentry = 'Module: dig'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    print ('\r\n[*] Running Dig against: ' + POE.target)

    a = pydig.query(POE.target, 'A')
    if (str(a) != '[]'):
        dig_output_data += 'A record: ' + str(a) + '\n'
    else:
        dig_output_data += 'A record: No results...\n'

    ns = pydig.query(POE.target, 'NS')
    if (str(ns) != '[]'):
        dig_output_data += 'NS: ' + str(ns) + '\n'
    else:
        dig_output_data += 'NS: No results...\n'

    cname = pydig.query(POE.target, 'CNAME')
    if (str(cname) != '[]'):
        dig_output_data += 'CNAME: ' + str(cname) + '\n'
    else:
        dig_output_data += 'CNAME: No results...\n'

    soa = pydig.query(POE.target, 'SOA')
    if (str(soa) != '[]'):
        dig_output_data += 'SOA: ' + str(soa) + '\n'
    else:
        dig_output_data += 'SOA: No results...\n'

    ptr = pydig.query(POE.target, 'PTR')
    if (str(ptr) != '[]'):
        dig_output_data += 'PTR: ' + str(ptr) + '\n'
    else:
        dig_output_data += 'PTR: No results...\n'

    mx = pydig.query(POE.target, 'MX')
    if (str(mx) != '[]'):
        dig_output_data += 'MX: ' + str(mx) + '\n'
    else:
        dig_output_data += 'MX: No results...\n'

    txt = pydig.query(POE.target, 'TXT')
    if (str(txt) != '[]'):
        dig_output_data += 'TXT: ' + str(txt) + '\n'
    else:
        dig_output_data += 'TXT: No results...\n'

    aaaa = pydig.query(POE.target, 'AAAA')
    if (str(aaaa) != '[]'):
        dig_output_data += 'AAAA: ' + str(aaaa) + '\n'
    else:
        dig_output_data += 'AAAA: No results...\n'

    ds = pydig.query(POE.target, 'DS')
    if (str(ds) != '[]'):
        dig_output_data += 'DS: ' + str(ds) + '\n'
    else:
        dig_output_data += 'DS: No results...\n'

    dnskey = pydig.query(POE.target, 'DNSKEY')
    if (str(dnskey) != '[]'):
        dig_output_data += 'DNSKEY: ' + str(dnskey) + '\n'
    else:
        dig_output_data += 'DNSKEY: No results...\n'

    cds = pydig.query(POE.target, 'CDS')
    if (str(cds) != '[]'):
        dig_output_data += 'CDS: ' + str(cds) + '\n'
    else:
        dig_output_data += 'CDS: No results...\n'

    cdnskey = pydig.query(POE.target, 'CDNSKEY')
    if (str(cdnskey) != '[]'):
        dig_output_data += 'CDNSKEY: ' + str(cdnskey) + '\n'
    else:
        dig_output_data += 'CDNSKEY: No results...\n'

    if (POE.debug == True):
        print ('[DEBUG]: ' + str(dig_output_data)) 
              
    try:        
        FI.WriteLogFile(output, dig_output_data)
        print (colored('[*] Dig data has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Dig data has been generated to file here: <a href=\"' + output + '\"> Dig Output </a>'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'True,'
    except:
        print (colored('[x] Unable to write Dig data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write Dig data to file'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'False,'
        return -1

    return 0
