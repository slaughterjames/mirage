#python imports
import sys
import os
import subprocess
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Info - Description: Executes a grep against the abuse.ch URLHaus blocklist feed.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    alx_output_data = []
    target_count = 0
    CSV_columns = 'id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\r'
    output = POE.logdir + 'URLHaus.csv'

    FI = fileio()

    print '\r\n[*] Running abuse.ch URLHaus grep against: ' + POE.target

    subproc = subprocess.Popen('grep ' + POE.target + ' /opt/mirage/feeds/URLHaus.txt', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for alx_data in subproc.stdout.readlines():           
        if (POE.debug == True):
            print '[DEBUG]: ' + alx_data 
        alx_output_data.append(alx_data)
    
    if (len(alx_output_data) > 0):
        target_count =  len(alx_output_data)
        print colored('[-] Target has ' + str(target_count) + ' entries in the abuse.ch URLHaus feed.', 'red', attrs=['bold'])                      
        if (POE.logging == True):
            newlogentry = '<strong>abuse.ch: Target has ' + str(target_count) + ' entries in the abuse.ch URLHaus feed.</strong>'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'True,'
            FI.WriteLogFile(output, CSV_columns) 
            for lines in alx_output_data:
                FI.WriteLogFile(output, lines)            
            print colored('[*] abuse.ch URLHaus data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
            newlogentry = 'abuse.ch URLHaus data has been generated to file here: <a href=\"' + output + '\"> URLHaus Output </a>'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
    else:
        print colored('[-] Target does not appear in the abuse.ch URLHaus feed', 'yellow', attrs=['bold'])    
        print colored('[x] abuse.ch URLHaus data not written to file', 'red', attrs=['bold'])
        POE.csv_line += 'False,'

    return 0
