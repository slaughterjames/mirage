#python imports
import sys
import os
import subprocess
from array import *
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Executes a WGet operation against the target
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    strings_dump = ''
    strings_output_data = ''
    wget_data = ''
    wget_output_data = '' 

    if not target.http_data:
        print colored('[-] No ports were found hosting an HTTP application.', 'red', attrs=['bold'])
        return -1 

    for port in target.http_data:
        if (debug == True):
            print '[DEBUG] Port: ' + str(port) + '\n'

        output = logdir + 'WGet_port_' + str(port) + '.txt'

        if (target.useragent.strip() == 'default'):
            if (debug == True):
                print '[DEBUG] wget --tries=1 -S --no-check-certificate -O ' + output + ' ' + target.target + ':' + str(port)

            #WGet flags: --tries=1 Limit tries to a host connection to 1.
            #            --no-check-certificate Will not balk when a site's certificate doesn't match the target domain.
            #            -O output to given filename.

            subproc = subprocess.Popen('wget --tries=1 --no-check-certificate -O ' + output + ' ' + target.target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for wget_data in subproc.stdout.readlines():
                if (wget_data.find('failed: Connection timed out.')!= -1):
                    print colored('[x] WGet - Connection timed out to host ' + target.target + ' port ' + str(port), 'red', attrs=['bold'])
                elif (wget_data.find('failed: No route to host.')!= -1):
                    print colored('[x] WGet - Connection failed.  No route to host ' + target.target + ' port ' + str(port), 'red', attrs=['bold'])
                wget_output_data += wget_data
                if (debug == True):
                    print wget_data
            print colored('[*] WGet file has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
            if (logging == True):
                newlogentry = 'WGet file has been generated to file here: <a href=\"' + output + '\"> WGet Port ' + str(port) + ' Output </a>'
                LOG.WriteLog(logdir, target.target, newlogentry)

        else:
            if (debug == True):
                print '[DEBUG] wget --user-agent=' + target.useragent.strip() + ' --tries=1 -S --no-check-certificate --save-headers -O ' + output + ' ' + target.target + ':' + str(port)

            #WGet flags: --tries=1 Limit tries to a host connection to 1.
            #            --user-agent Will identify as a browser agent and not WGet
            #            --no-check-certificate Will not balk when a site's certificate doesn't match the target domain.
            #            -O output to given filename.

            subproc = subprocess.Popen('wget --user-agent=' + target.useragent + ' --tries=1 --no-check-certificate -O ' + output + ' ' + target.target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for wget_data in subproc.stdout.readlines():
                if (wget_data.find('failed: Connection timed out.')!= -1):
                    print colored('[x] Connection timed out to host ' + target.target + ' port ' + str(port), 'red', attrs=['bold'])
                elif (wget_data.find('failed: No route to host.')!= -1):
                    print colored('[x] Connection failed.  No route to host ' + target.target + ' port ' + str(port), 'red', attrs=['bold'])
                wget_output_data += wget_data
                if (debug == True):
                    print wget_data
            print colored('[*] WGet file has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
            if (logging == True):
                newlogentry = 'WGet file has been generated to file here: <a href=\"' + output + '\"> WGet Port ' + str(port) + ' Output </a>'
                LOG.WriteLog(logdir, target.target, newlogentry)

    return 0
