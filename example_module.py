#python imports
import sys
import os
import subprocess
from termcolor import colored

#third-party imports
#Put andy third-party imports here

#programmer generated imports
#Add your own python library imports here

'''
***BEGIN DESCRIPTION***
Type: <Your classification> - Description: <Your Description of what your module does> Appears when --listmodules is used as a command line argument
***END DESCRIPTION***
'''
def POE(POE):

    #Make sure this file goes into the modules directory.  For instance, /opt/mirage/modules.
    #To enable, add the following entry in the configuration file, mirage.conf 
    #under the addins heading (without the .py file extension and the "#").  For instance:
    #
        #{
        #    "info": "My_New_Module"
        #},
    #POE = Point Of Entry - Object passed into the module containing run information about the program 
    #                     - Is a manifestation of the target class.  Attributes contained: 
    #POE.url = True/False value of the --url command line argument
    #POE.ip = True/False value of the --ip command line argument
    #POE.domain = True/False value of the --domain command line argument
    #POE.target = target domain or IP value of the host being investigated
    #POE.useragent = useragent string value read in from the configuration file
    #POE.logdir = Log directory specified in the configuration file
    #POE.logging = True/False value of the logging argument from the configuration file
    #POE.csv_line = Line for output to a CSV file if logging is enabled and the --csv command line argument is used
    #POE.debug = True/False value of the --debug command line argument
    #POE.http_data = Array of ports found to have HTTP applications running on them if --type active or --type all command line arguments are used
    #POE.https_data = Array of ports found to have HTTPS applications running on them if --type active or --type all command line arguments are used

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    output = POE.logdir + 'Your_Output.txt'

    print '\r\n[*] Running your module against: ' + POE.target

    #Do some stuff

    #if your stuff is true                     
        print colored('[-] Stuff is true.', 'green', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'Stuff is true.'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'True,'       
    #If your stuff is false
        print colored('[-] Stuff is false.  This could be bad', 'red', attrs=['bold'])
        if (POE.logging == True):
            newlogentry = 'Stuff is false. <strong>This could be bad.</strong>'
            LOG.WriteLog(POE.logdir, POE.target, newlogentry)   
            POE.csv_line += 'False,' 
        print colored('[x] Stuff not written to file.', 'red', attrs=['bold']

    #Unless there is an exception, always return 0 upon completion.
    return 0
