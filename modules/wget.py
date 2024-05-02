#python imports
import subprocess
from array import *
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Passive/Active - Description: Executes a WGet operation against the target
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    wget_data = ''
    http_data = []

    if (POE.logging == True):
        newlogentry = 'Module: wget'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    if not POE.http_data:
        print (colored('\r\n[-] WGet - Active scan not undertaken for HTTP ports.  Defaulting to 80 and 443...', 'yellow', attrs=['bold']))
        http_data = [80, 443]
    else:
        http_data = POE.http_data  

    for port in http_data:
        if (POE.debug == True):
            print ('[DEBUG] Port: ' + str(port) + '\n')

        output = POE.logdir + 'WGet_port_' + str(port) + '.txt'

        print ('\r\n[*] Running WGet against: ' + POE.target + ':' + str(port))

        if (POE.useragent.strip() == 'default'):
            if (POE.debug == True):
                print ('[DEBUG] wget --tries=1 -S --no-check-certificate --timeout=60 -O ' + output + ' ' + POE.target + ':' + str(port))

            #WGet flags: --tries=1 Limit tries to a host connection to 1.
            #            --no-check-certificate Will not balk when a site's certificate doesn't match the target domain.
            #            --timeout=60 Set the maximum wait time to 60 seconds instead of waiting indefinitely
            #            -O output to given filename.

            subproc = subprocess.Popen('wget --tries=1 --no-check-certificate --timeout=60 -O ' + output + ' ' + POE.target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for wget_data in subproc.stdout.readlines():
                if (b'Connection timed out' in wget_data):
                    print (colored('[x] WGet - Connection timed out to host ' + POE.target + ' port ' + str(port) + '...', 'red', attrs=['bold']))
                    if (POE.logging == True):
                        newlogentry = 'Connection timed out to host'
                        LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
                elif (b'failed: No route to host.'in wget_data):
                    print (colored('[x] WGet - Connection failed.  No route to host ' + POE.target + ' port ' + str(port), 'red', attrs=['bold']))
                    if (POE.logging == True):
                        newlogentry = 'Connection failed.  No route to host'
                        LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)

            print (colored('[*] WGet file has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'WGet file has been generated to file here: <a href=\"' + output + '\"> WGet Port ' + str(port) + ' Output </a>'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)

        else:
            if (POE.debug == True):
                print ('[DEBUG] wget --user-agent=' + POE.useragent.strip() + ' --tries=1 -S --no-check-certificate --save-headers --timeout=60 -O ' + output + ' ' + POE.target + ':' + str(port))

            #WGet flags: --tries=1 Limit tries to a host connection to 1.
            #            --user-agent Will identify as a browser agent and not WGet
            #            --no-check-certificate Will not balk when a site's certificate doesn't match the target domain.
            #            --timeout=60 Set the maximum wait time to 60 seconds instead of waiting indefinitely
            #            -O output to given filename.

            subproc = subprocess.Popen('wget --user-agent=' + POE.useragent + ' --tries=1 --no-check-certificate --timeout=60 -O ' + output + ' ' + POE.target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for wget_data in subproc.stdout.readlines():
                if (b'Connection timed out' in wget_data):
                    print (colored('[x] WGet - Connection timed out to host ' + POE.target + ' port ' + str(port) + '...', 'red', attrs=['bold']))
                    if (POE.logging == True):
                        newlogentry = 'Connection timed out to host'
                        LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
                elif (b'failed: No route to host.'in wget_data):
                    print (colored('[x] WGet - Connection failed.  No route to host ' + POE.target + ' port ' + str(port), 'red', attrs=['bold']))
                    if (POE.logging == True):
                        newlogentry = 'Connection failed.  No route to host'
                        LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            print (colored('[*] WGet file has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'WGet file has been generated to file here: <a href=\"' + output + '\"> WGet Port ' + str(port) + ' Output </a>'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)

    return 0