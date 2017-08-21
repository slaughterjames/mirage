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

    for port in target.http_data:
        if (debug == True):
            print 'Port: ' + str(port) + '\n'

        output = logdir + 'index_port' + str(port) + '.html'

        if (target.useragent.strip() == 'default'):
            if (debug == True):
                print 'wget --tries=1 -S --no-check-certificate -O ' + output + ' ' + target.target + ':' + str(port)

            #WGet flags: --tries=1 Limit tries to a host connection to 1.
            #            --no-check-certificate Will not balk when a site's certificate doesn't match the target domain.
            #            -O output to given filename.

            subproc = subprocess.Popen('wget --tries=1 --no-check-certificate -O ' + output + ' ' + target.target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for wget_data in subproc.stdout.readlines():
                wget_output_data += wget_data
                if (debug == True):
                    print wget_data

        else:
            if (debug == True):
                print 'wget --user-agent=' + target.useragent.strip() + ' --tries=1 -S --no-check-certificate --save-headers -O ' + output + ' ' + target.target + ':' + str(port)

            #WGet flags: --tries=1 Limit tries to a host connection to 1.
            #            --user-agent Will identify as a browser agent and not WGet
            #            --no-check-certificate Will not balk when a site's certificate doesn't match the target domain.
            #            -O output to given filename.

            subproc = subprocess.Popen('wget --user-agent=' + target.useragent + ' --tries=1 --no-check-certificate -O ' + output + ' ' + target.target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for wget_data in subproc.stdout.readlines():
                wget_output_data += wget_data
                if (debug == True):
                    print wget_data

    return 0
