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
Executes a traceroute against the target.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    trt_output_data = ''
    output = logdir + 'Traceroute.txt'

    FI = fileio()

    print '\r\n[*] Running Traceroute against: ' + target.target

    subproc = subprocess.Popen('traceroute ' + target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for trt_data in subproc.stdout.readlines():
        if (debug == True):
            print '[DEBUG]: ' + trt_data 
        trt_output_data += trt_data 
              
    try:        
        FI.WriteLogFile(output, trt_output_data)
        print colored('[*] Traceroute data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
        if (logging == True):
            newlogentry = 'Traceroute data has been generated to file here: <a href=\"' + output + '\"> Traceroute Output </a>'
            LOG.WriteLog(logdir, target.target, newlogentry)
    except:
        print colored('[x] Unable to write Traceroute data to file', 'red', attrs=['bold'])  
        if (logging == True):
            newlogentry = 'Unable to write Traceroute data to file'
            LOG.WriteLog(logdir, target.target, newlogentry)
        return -1

    return 0
