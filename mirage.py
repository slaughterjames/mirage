#!/usr/bin/python
'''
Mirage v0.8 - Copyright 2019 James Slaughter,
This file is part of Mirage v0.8.

Mirage v0.8 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Mirage v0.8 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Mirage v0.8.  If not, see <http://www.gnu.org/licenses/>
'''

'''
mirage.py - This is the main file of the program and is the jumping off point
into the rest of the code
'''

#python imports
import sys
import os
import time
import subprocess
import re
import json
import simplejson
import csv
from array import *
from termcolor import colored

#programmer generated imports
from targetclass import targetclass
from portmap import portmap
from controller import controller
from logger import logger 
from fileio import fileio
from mms import mms

'''
Usage()
Function: Display the usage parameters when called
'''
def Usage():
    print 'Usage: [required] [--ip|--domain|--url] [--target|--targetlist] --type --modules [optional] --sleeptime --url --output --csv --listmodules --listaddintypes --updatefeeds --debug --help'
    print 'Example: /opt/mirage/mirage.py --ip --target 192.168.1.1 --type "info passive active"--modules all --output /your/directory --debug'
    print 'Required Arguments:'
    print '--ip - The target being investigated is an IP address'
    print 'OR'
    print '--domain - The target being investigated is a domain'
    print 'OR'
    print '--url - The target being investigated is a full URL'
    print '--target - Single target host to examine'
    print 'OR'
    print '--targetlist - List of hosts to examine in one session'
    print '--type - info, passive, active or all'
    print '--modules - all or specific'
    print 'Optional Arguments:'
    print '--sleeptime - Choose the sleep period between targets when --targetlist is used.  Default is 15 seconds.  Value must be between 0 and 120.'
    print '--output - Choose where you wish the output to be directed'
    print '--csv - Output to csv if logging is enabled'
    print '--listmodules - Prints a list of available modules and their descriptions.'
    print '--listaddintypes - Prints a list of available addin types as defined in the mirage.conf file.  Defines a group of modules to run.'
    print '--updatefeeds - Update the feeds used for the info type switch.'
    print '--debug - Prints verbose logging to the screen to troubleshoot issues with a recon installation.'
    print '--help - You\'re looking at it!'
    sys.exit(-1)

'''
ConfRead()
Function: - Reads in the mirage.conf config file
'''
def ConfRead():
        
    ret = 0
    intLen = 0
    FConf = fileio()
    data = ''

    try:
        #Conf file hardcoded here
        with open('/opt/mirage/mirage.conf', 'r') as read_file:
            data = json.load(read_file)
    except:
        print colored('[x] Unable to read configuration file.', 'red', attrs=['bold'])
        return -1

    
    CON.logger = data['logger']
    CON.logroot = data['logroot']
    CON.useragent = data['useragent']
    CON.useragent = CON.useragent.strip()
    CON.sleeptime = data['sleeptime']
    if ((int(CON.sleeptime.strip()) < 0) or (int(CON.sleeptime.strip()) > 120)):
        CON.sleeptime = '7'
        print colored('[x] sleeptime value out of range.  sleeptime must be between 0 and 120 seconds.', 'red', attrs=['bold'])
        print colored('[-] sleeptime defaulting to 7 seconds.', 'yellow', attrs=['bold'])  
    CON.modulesdir = data['modulesdir']
    CON.types = data['addintypes']
    CON.addins = data['addins']
  
    if (CON.debug == True):
        print '[DEBUG] data: ', data
        print '[DEBUG] CON.logger: ' + str(CON.logger)
        print '[DEBUG] CON.logroot: ' + str(CON.logroot)
        print '[DEBUG] CON.useragent: ' + str(CON.useragent)
        print '[DEBUG] CON.sleeptime: ' + str(CON.sleeptime)
        print '[DEBUG] CON.modulesdir: ' + str(CON.modulesdir)
        print '[DEBUG] CON.types: ' + str(CON.types)
 
        for a_addins in CON.addins: 
            for key, value in a_addins.iteritems():
                print '[DEBUG] CON.addins key: ' + key + ' value: ' + value
            
    if (CON.debug == True):
       print '[*] Finished configuration.'
       print ''
            
    return 0

'''
Parse() - Parses program arguments
'''
def Parse(args):        
    option = ''
                    
    print '[*] Arguments: '
    for i in range(len(args)):
        if args[i].startswith('--'):
            option = args[i][2:]
                
            if option == 'help':
                return -1                                   

            if option == 'target':
                CON.target = args[i+1]
                CON.singletarget = True
                print option + ': ' + CON.target

            if option == 'targetlist':
                CON.targetlist = args[i+1]
                CON.singletarget = False
                print option + ': ' + CON.targetlist 

            if option == 'type':
                CON.type = args[i+1].split()
                for type_out in CON.type:
                    print option + ': ' + type_out

            if option == 'modules':
                CON.modules = args[i+1]
                print option + ': ' + CON.modules

            if option == 'sleeptime':
                CON.sleeptime = args[i+1]
                print option + ': ' + str(CON.sleeptime)
   
            if option == 'domain':
                CON.domain = True
                print option + ': ' + str(CON.domain)

            if option == 'ip':
                CON.ip = True
                print option + ': ' + str(CON.ip)

            if option == 'url':
                CON.url = True
                print option + ': ' + str(CON.url)            
            
            if option == 'output':
                #This is an optional param and needs to be checked at read time
                CON.output = args[i+1]
                print option + ': ' + CON.output
                if len(CON.output) < 3:
                    print colored('[x] output must be a viable location.', 'red', attrs=['bold'])          
                    print ''
                    return -1

            if option == 'csv':
                CON.csv = True
                print option + ': ' + str(CON.csv)
                
            if option == 'debug':
                CON.debug = True
                print option + ': ' + str(CON.debug)               

    #listmodules, listaddintypes and updatefeeds will cause all other params to be ignored
    if option == 'listmodules':
        CON.listmodules = True
        print option + ': ' + str(CON.listmodules)
        print ''

    elif option == 'listaddintypes':
        CON.listaddintypes = True
        print option + ': ' + str(CON.listaddintypes)
        print ''

    elif option == 'updatefeeds':
        CON.updatefeeds = True
        print option + ': ' + str(CON.updatefeeds)
        print ''

    else:                                        
        #These are required params so length needs to be checked after all 
        #are read through         
        if ((len(CON.target) < 3) and (len(CON.targetlist) < 3)):
            print colored('[x] target or targetlist are required arguments.', 'red', attrs=['bold'])
            print ''
            return -1         
    
        if len(CON.modules) < 3:
            print colored('[x] modules is a required argument.', 'red', attrs=['bold'])
            print ''
            return -1

        if len(CON.type) < 1:
            print colored('[x] type is a required argument.', 'red', attrs=['bold'])
            print ''
            return -1 

        if ((len(CON.target) > 0) and (len(CON.targetlist) > 0)):
            print colored('[x] target argument cannot be used with targetlist.', 'red', attrs=['bold'])        
            print ''
            return -1

        if ((CON.domain == True) and ((CON.ip == True) or (CON.url == True))):
            print colored('[x] domain argument cannot be used with ip or url.', 'red', attrs=['bold'])
            print ''
            return -1

        if ((CON.ip == True) and ((CON.domain == True) or (CON.url == True))):
            print colored('[x] ip argument cannot be used with domain or url.', 'red', attrs=['bold'])
            print ''
            return -1         

        if ((CON.url == True) and ((CON.domain == True) or (CON.ip == True))):
            print colored('[x] url argument cannot be used with domain or ip.', 'red', attrs=['bold'])
            print ''
            return -1

        if (CON.sleeptime != ''):
            if ((int(CON.sleeptime.strip()) < 0) or (int(CON.sleeptime.strip()) > 120)):
                print colored('[x] sleeptime value out of range.  sleeptime must be between 0 and 120 seconds.', 'red', attrs=['bold'])
                print ''
                return -1
                                   
    return 0

'''
ListModules()
Function: - List all available modules and their descriptions
'''
def ListModules():
    FConf = fileio()
    count = 0
    addins = ''

    for addins in CON.addins: 
        for key, value in addins.iteritems():
            FConf.ReadFile(CON.modulesdir.strip() + value.strip() + '.py')
            for line in FConf.fileobject:
                if (count == 1):
                    print '[*] ' + value + ': ' + line
                    count = 0
                    break
                if (line.find('***BEGIN DESCRIPTION***') != -1):
                    count = 1              

    return 0

'''
ListModules()
Function: - List all available modules and their descriptions
'''
def ListAddinTypes():
    FConf = fileio()
    count = 0
    addins = ''

    print '[*] Addin types available are:\n'
    for type_out in CON.types:
        print '[*] Type: ' + type_out

    print '[*] --Or-- type all'               

    return 0

'''
UpdateFeeds()
Function: - Update the feeds used for the info type switch.
'''
def UpdateFeeds():

    subproc = os.system("gnome-terminal -e 'bash -c \"sudo /opt/mirage/updatefeeds.sh; exec bash\"'")    

    return 0


'''
TargetRead()
Function: - Reads in a list of targets from a file
'''
def TargetRead():

    FConf = fileio()
    try:
        #Conf file hardcoded here
    	FConf.ReadFile(CON.targetlist)
    except:
        print '[x] Unable to read target file: ' + CON.targetlist
        print colored('[x] Unable to read target file: ' + CON.targetlist, 'red', attrs=['bold'])
        return -1
    
    for line in FConf.fileobject:
        CON.listoftargets.append(line)
        if (CON.debug == True):
            print '[DEBUG]: ' + line 

    CON.targetlistsize = len(CON.listoftargets)
        
    print '[*] Finished reading target file.'
    print '[*] Target file size: ' + str(CON.targetlistsize) + ' entries.'
    print ''
            
    return 0

'''
Execute()
Function: - Does the doing against a target
'''
def Execute():
    if len(CON.output) != 0:
        CON.logdir = CON.output.strip() + '/' + CON.targetobject.target.strip() + '/'
        CON.targetobject.logdir = CON.output.strip() + '/' + CON.targetobject.target.strip() + '/'
    else:
        CON.logdir = CON.logroot.strip() + CON.targetobject.target.strip() + '/'
        CON.targetobject.logdir = CON.logroot.strip() + CON.targetobject.target.strip() + '/'

    if (CON.logging == True):
        LOG = logger()                           

    if (CON.debug == True):
        print 'LOG variables:\n' 
        print 'logdir: ' + CON.logdir + '\n'
        print ''        

    if not os.path.exists(CON.logdir):
        os.makedirs(CON.logdir)
    else:
        CON.targetdealtwith = True
        print colored('[-] Sample: ' + CON.targetobject.target + ' has previously been dealt with...Skipping.', 'yellow', attrs=['bold'])
        return -1

    if (CON.logging == True):
        try:
            print '[*] Creating log file'
            LOG.LogCreate(CON.logdir, CON.targetobject.target)                
        except Exception, e:
            print '[x] Unable to create LOG object: ', e
            print colored('[x] Unable to create LOG object: ', e, 'red', attrs=['bold'])
            Terminate(-1)

    if (('active' in CON.type) or ('all' in CON.type)):
        PMAP = portmap()
        CON.targetobject = PMAP.Map(CON.targetobject, CON.logging, CON.logdir, CON.debug)

    ret = MMS.OrganizeModules(CON.targetobject)
    if (ret !=0 ):
        print '[x] Unable to continue module execution.  Terminating...'
        print colored('[x] Unable to continue module execution.  Terminating...', 'red', attrs=['bold'])
        Terminate(ret)     

    if (CON.logging == True):
        newlogentry = 'Program Complete'
        LOG.WriteLog(CON.logdir, CON.targetobject.target, newlogentry)
        newlogentry = ''
        LOG.LogFooter(CON.logdir, CON.targetobject.target)

    CON.logdir = ''

'''
Terminate()
Function: - Attempts to exit the program cleanly when called  
'''
     
def Terminate(exitcode):
    sys.exit(exitcode)

'''
This is the mainline section of the program and makes calls to the 
various other sections of the code
'''

if __name__ == '__main__':
    
        ret = 0

        Table_Data = ()

        CON = controller()
                   
        ret = Parse(sys.argv)

        if (ret == -1):
            Usage()
            Terminate(ret) 

        ret = ConfRead()        

        if (ret == -1):
            print '[x] Terminated reading the configuration file...'
            Terminate(ret)

        if (CON.listmodules == True):
            ListModules()
            Terminate(0)

        if (CON.listaddintypes == True):
            ListAddinTypes()
            Terminate(0)

        if (CON.updatefeeds == True):
            UpdateFeeds()
            Terminate(0)

        if ('all' in CON.type):
            for addins in CON.addins: 
                for key, value in addins.iteritems():
                    CON.module_manifest.append(value)
            MMS = mms(CON.module_manifest, CON.modulesdir, CON.modules, CON.debug)
        else:
             for type in CON.type:
                 if (type in CON.types):
                     print '[*] Type is ' + type
                     for addins in CON.addins: 
                         for key, value in addins.iteritems():
                             if (key == type):
                                 CON.module_manifest.append(value)
                     MMS = mms(CON.module_manifest, CON.modulesdir, CON.modules, CON.debug) 
                 else:
                     print colored('[x] Type ' + type + ' is not recognized...\n', 'red', attrs=['bold'])
                     print 'Type must be one of the following:'
                     for types in CON.types:
                         print types
                     print 'all'
                     print '[x] Terminating...'
                     Terminate(-1)   

        if (CON.debug == True):
            print '[DEBUG]: ', CON.module_manifest

        if (CON.logger.strip() == 'true'): 
            CON.logging = True
            print '[*] Logger is active'        
        else:
            print '[-] Logger not active'

        #Logging must be enabled in order to output to CSV
        if (CON.csv == True):
            if (CON.logging == False):                
                print colored('[-] Logging must be enabled in order to output to CSV.  Disregarding...', 'yellow', attrs=['bold'])
                CON.csv = False
            if (CON.singletarget == True):
                print colored('[-] A targetlist must be used instead of a single target in order to output to CSV.  Disregarding...', 'yellow', attrs=['bold'])
                CON.csv = False

        if (CON.singletarget == True):
            CON.targetobject = targetclass(CON.logging, CON.csv_line, CON.debug, CON.url, CON.ip, CON.domain, CON.target, CON.useragent)
            Execute()
            del CON.targetobject
        else:
            TargetRead()
            Count = 0
                       
            if (CON.logging == True):
                if len(CON.output) != 0:
                    CON.reportdir = CON.output.strip() + '/'
                else:
                    CON.reportdir = CON.logroot.strip() + '/'  

                if not os.path.exists(CON.reportdir):
                    os.makedirs(CON.reportdir)    
         
                try: 
                    if (CON.csv == True):
                        CON.csv_filename = CON.reportdir + 'logroot.csv'
 
                        if (CON.debug == True):
                            print '[DEBUG]: CSV Field Names: ', CON.module_manifest

                        with open(CON.csv_filename, mode='wb') as logroot_file:
                            logroot_writer = csv.DictWriter(logroot_file, fieldnames=["Target"] + CON.module_manifest)
                            logroot_writer.writeheader()                                               
                except Exception, e:
                    print '[x] Unable to create CSV File: ', e
                    Terminate(-1)  
              
            for target in CON.listoftargets:
                Count += 1

                CON.targetobject = targetclass(CON.logging, CON.csv_line, CON.debug, CON.url, CON.ip, CON.domain, CON.target, CON.useragent)
                CON.targetobject.target = target.strip()

                print '[*] Executing against target ' + str(Count) + ' of ' + str(CON.targetlistsize) + ' - ' + CON.targetobject.target + '\r'

                if (CON.csv == True):
                    CON.targetobject.csv_line += CON.targetobject.target + ','
 
                Execute()                

                if (CON.debug==True):
                    print '[DEBUG]: ' + target

                if (CON.logging == True):
                    target_link = '<a href=\"' + CON.logdir + CON.targetobject.target + '/' + CON.targetobject.target + '.html' + '\">' + CON.targetobject.target + '</a>'
                    if (CON.csv == True):
                        f = open(CON.csv_filename,'a')
                        f.write(CON.targetobject.csv_line + '\n')
                        f.close()                

                del CON.targetobject
                if (CON.targetdealtwith == False):
                    if (Count != CON.targetlistsize):
                        print '[*] Sleeping ' + CON.sleeptime.strip() + ' seconds before next request...'
                        print '*' * 100
                        time.sleep(int(CON.sleeptime.strip()))
                else:
                    CON.targetdealtwith = False    
    
	    print ''
        print colored('[*] Program Complete', 'green', attrs=['bold'])

        Terminate(0)
'''
END OF LINE
'''
