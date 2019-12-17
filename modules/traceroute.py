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
Type: Passive - Description: Executes a traceroute against the target.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    trt_output_data = ''
    not_found_flag = 0
    output = POE.logdir + 'Traceroute.txt'

    FI = fileio()

    print '\r\n[*] Running Traceroute against: ' + POE.target

    subproc = subprocess.Popen('traceroute ' + POE.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for trt_data in subproc.stdout.readlines():
        if (POE.debug == True):
            print '[DEBUG]: ' + trt_data 
        trt_output_data += trt_data 
        if (trt_output_data.find('Name or service not known')!= -1): 
            not_found_flag = 1    

    try:
        if (not_found_flag == 1):
            print colored('[x] Traceroute: Name or service not known.  Traceroute data not written to file.', 'red', attrs=['bold'])
            if (POE.logging == True):
                newlogentry = 'Traceroute: Name or service not known.  Traceroute data not written to file'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
                POE.csv_line += 'False,'
        else:        
            FI.WriteLogFile(output, trt_output_data)
            print colored('[*] Traceroute data has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
            if (POE.logging == True):
                newlogentry = 'Traceroute data has been generated to file here: <a href=\"' + output + '\"> Traceroute Output </a>'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
                POE.csv_line += 'True,'
    except:
        print colored('[x] Exception.  Unable to write Traceroute data to file!', 'red', attrs=['bold'])  
        if (logging == True):
            newlogentry = 'Exception.  Unable to write Traceroute data to file!'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'False,'
        return -1

    return 0
