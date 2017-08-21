#!/usr/bin/python
'''
Mirage v0.4 - Copyright 2017 James Slaughter,
This file is part of Mirage v0.4.

Mirage v0.4 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Mirage v0.4 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Mirage v0.4.  If not, see <http://www.gnu.org/licenses/>.
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
import urllib
import urllib2
from array import *

#programmer generated imports
from targetclass import targetclass
from portmap import portmap
from controller import controller
from logger import logger, Table, TableRow, TableCell 
from fileio import fileio

'''
Usage()
Function: Display the usage parameters when called
'''
def Usage():
    print 'Usage: [required] [--ip|--domain|--url] [--target|--targetlist] --type --modules [optional] --url --output --listmodules -updatefeeds --debug --help'
    print 'Example: /opt/mirage/mirage.py --ip --target 192.168.1.1 --type info --modules all --output /your/directory --debug'
    print 'Required Arguments:'
    print '--ip - the target being investigated is an IP address'
    print 'OR'
    print '--domain - the target being investigated is a domain'
    print 'OR'
    print '--url - the target being investigated is a full URL'
    print '--target - single target host to examine'
    print 'OR'
    print '--targetlist - list of hosts to examine in one session'
    print '--type - info, passive, active or all'
    print '--modules - all or specific'
    print 'Optional Arguments:'
    print '--output - choose where you wish the output to be directed'
    print '--listmodules - prints a list of available modules and their descriptions.'
    print '--updatefeeds - update the feeds used for the info type switch.'
    print '--debug - prints verbose logging to the screen to troubleshoot issues with a recon installation.'
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
    try:
        #Conf file hardcoded here
    	FConf.ReadFile('/opt/mirage/mirage.conf')
    except:
        print '[x] Unable to read configuration file'
        return -1
    
    for line in FConf.fileobject:
        intLen = len(line)            
        if (CON.debug == True):
            print line
        if (line.find('logger') != -1):                
            CON.logger = line[7:intLen]
        elif (line.find('logroot') != -1):                
            CON.logroot = line[8:intLen]
        elif (line.find('useragent') != -1):
            CON.useragent = line[10:intLen]
        elif (line.find('apikey') != -1):
            CON.apikey = line[7:intLen]
        elif (line.find('modulesdir') != -1):
            CON.modulesdir = line[11:intLen]         
        elif (line.find('infoaddin') != -1):
            CON.infoaddins.append(line[10:intLen])
        elif (line.find('activeaddin') != -1):
            CON.activeaddins.append(line[12:intLen])
        elif (line.find('passiveaddin') != -1):
            CON.passiveaddins.append(line[13:intLen])
        else:
            if (CON.debug == True): 
                print ''
        
    if (CON.debug == True):
        print 'Finished configuration.'
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
                CON.type = args[i+1]
                print option + ': ' + CON.type

            if option == 'modules':
                CON.modules = args[i+1]
                print option + ': ' + CON.modules
   
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
                    print '[x] output must be a viable location'           
                    print ''
                    return -1
                
            if option == 'debug':
                CON.debug = True
                print option + ': ' + str(CON.debug)               

    #listmodules and updatefeeds will cause all other params to be ignored
    if option == 'listmodules':
        CON.listmodules = True
        print option + ': ' + str(CON.listmodules)
        print ''

    elif option == 'updatefeeds':
        CON.updatefeeds = True
        print option + ': ' + str(CON.updatefeeds)
        print ''
    else:                                        
        #These are required params so length needs to be checked after all 
        #are read through         
        if ((len(CON.target) < 3) and (len(CON.targetlist) < 3)):
            print 'target or targetlist are required arguments'           
            print ''
            return -1         
    
        if len(CON.modules) < 3:
            print 'modules is a required argument'           
            print ''
            return -1

        if len(CON.type) < 2:
            print 'type is a required argument'           
            print ''
            return -1 

        if ((len(CON.target) > 0) and (len(CON.targetlist) > 0)):
            print 'target argument cannot be used with targetlist'
            print ''
            return -1

        if ((CON.domain == True) and ((CON.ip == True) or (CON.url == True))):
            print 'domain argument cannot be used with ip or url'
            print ''
            return -1

        if ((CON.ip == True) and ((CON.domain == True) or (CON.url == True))):
            print 'ip argument cannot be used with domain or url'
            print ''
            return -1         

        if ((CON.url == True) and ((CON.domain == True) or (CON.ip == True))):
            print 'url argument cannot be used with domain or ip'
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
             
    for addins in CON.infoaddins:
        FConf.ReadFile(CON.modulesdir.strip() + addins.strip() + '.py')
        for line in FConf.fileobject:
            if (count == 1):
                print '[*] ' + addins + line
                count = 0
                break
            if (line.find('***BEGIN DESCRIPTION***') != -1):
                count = 1
    
    for addins in CON.activeaddins:
        FConf.ReadFile(CON.modulesdir.strip() + addins.strip() + '.py')
        for line in FConf.fileobject:
            if (count == 1):
                print '[*] ' + addins + line
                count = 0
                break
            if (line.find('***BEGIN DESCRIPTION***') != -1):
                count = 1   

    for addins in CON.passiveaddins:
        FConf.ReadFile(CON.modulesdir.strip() + addins.strip() + '.py')
        for line in FConf.fileobject:
            if (count == 1):
                print '[*] ' + addins + line
                count = 0
                break
            if (line.find('***BEGIN DESCRIPTION***') != -1):
                count = 1     

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
        return -1
    
    for line in FConf.fileobject:
        CON.listoftargets.append(line)
        if (CON.debug == True):
            print '[DEBUG]: ' + line 
        
    print '[*] Finished reading target file.'
    print ''
            
    return 0

'''
Execute()
Function: - Does the doing against a target
'''
def Execute():
    if len(CON.output) != 0:
        CON.logdir = CON.output.strip() + '/' + CON.targetobject.target.strip() + '/'
    else:
        CON.logdir = CON.logroot.strip() + CON.targetobject.target.strip() + '/'

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
        print '[x] Sample: ' + CON.targetobject.target + ' has previously been dealt with...Skipping.'
        return -1

    if (CON.logging == True):
        try:
            print '[*] Creating log file'
            LOG.LogCreate(CON.logdir, CON.targetobject.target)                
        except Exception, e:
            print '[x] Unable to create LOG object: ', e
            Terminate(-1)

    if (CON.type == 'active'):
        PMAP = portmap()
        CON.targetobject = PMAP.Map(CON.targetobject, CON.logging, CON.logdir, CON.debug)

    CON.OrganizeModules()    

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
            print 'Terminated reading the configuration file...'
            Terminate(ret)

        if (CON.listmodules == True):
            ListModules()
            Terminate(0)

        if (CON.updatefeeds == True):
            UpdateFeeds()
            Terminate(0)

        if (CON.logger.strip() == 'true'): 
            CON.logging = True
            print '[*] Logger is active'        
        else:
            print '[-] Logger not active'

        if (CON.singletarget == True):
            CON.targetobject = targetclass(CON.url, CON.ip, CON.domain, CON.target, CON.useragent)
            Execute()
            del CON.targetobject
        else:
            TargetRead()
            numberOfTargets = 0
            Count = 0
            for targets in CON.listoftargets:
                numberOfTargets += 1           
            
            if (CON.logging == True):
                if len(CON.output) != 0:
                    CON.reportdir = CON.output.strip() + '/'
                else:
                    CON.reportdir = CON.logroot.strip() + '/'  

                if not os.path.exists(CON.reportdir):
                    os.makedirs(CON.reportdir)    
         
                try:
                    print '[*] Creating report file: ' + CON.reportdir + 'logroot.html'
                    REP = logger()
                    REP.ReportCreate(CON.reportdir, CON.targetlist) 
                    if ((CON.type == 'all') or ((CON.type=='info') and (CON.modules=='all'))):
                        TB = Table(header_row=['Target', 'Alexa', 'Abuse.ch Ransomware Domains', 'Abuse.ch Ransomware URLs', 'Abuse.ch Ransomware IPs', 'VirusTotal',   						        'IBM XForce'],                        
                            col_width=['10', '10', '10%', '10%', '10%', '10%', '10%'],
                            col_align=['center', 'center', 'center', 'center', 'center', 'center', 'center'],
                            col_styles=['font-size: large','font-size: large', 'font-size: large', 'font-size: large', 'font-size: large', 'font-size: large', 'font-size: large'])  
                    elif ((CON.type=='info') and (CON.modules!='all')):
                        if (CON.modules == 'alexa'):
                            TB = Table(header_row=['Target', 'Alexa'])
                        elif (CON.modules=='abuse_ch_ransomware_domains'):
                            TB = Table(header_row=['Target', 'Abuse.ch Ransomware Domains'])
                        elif (CON.modules=='abuse_ch_ransomware_urls'):
                            TB = Table(header_row=['Target', 'Abuse.ch Ransomware URLS'])                       
                        elif (CON.modules=='abuse_ch_ransomware_ips'):
                            TB = Table(header_row=['Target', 'Abuse.ch Ransomware IPs'])
                        elif (CON.modules=='VTReputation'):
                            TB = Table(header_row=['Target', 'VirusTotal'])
                        else:
                            TB = Table(header_row=['Target', 'IBM XForce'])
                    else:
                        TB = Table(header_row=['Target'])            
                except Exception, e:
                    print '[x] Unable to create REP object: ', e
                    Terminate(-1)                
            for target in CON.listoftargets:
                Count += 1

                CON.targetobject = targetclass(CON.url, CON.ip, CON.domain, CON.target, CON.useragent)
                CON.targetobject.target = target.strip()                     
 
                Execute()                

                if (CON.debug==True):
                    print target

                if (CON.logging == True):

                    target_link = '<a href=\"' + CON.logdir + CON.targetobject.target + '/' + CON.targetobject.target + '.html' + '\">' + CON.targetobject.target + '</a>'

                    if ((CON.type == 'all') or ((CON.type=='info') and (CON.modules=='all'))):

                        if (CON.targetobject.alexa == False):
                            alexa = TableCell(str(CON.targetobject.alexa), bgcolor='red') 
                        else:
                            alexa = TableCell(str(CON.targetobject.alexa), bgcolor='green')

                        if (CON.targetobject.abuse_ch_ransomware_domains == False):     
                            abuse_rsw_domains = TableCell(str(CON.targetobject.abuse_ch_ransomware_domains), bgcolor='green')
                        else:
                            abuse_rsw_domains = TableCell(str(CON.targetobject.abuse_ch_ransomware_domains), bgcolor='red')

                        if (CON.targetobject.abuse_ch_ransomware_urls == False):
                            abuse_rsw_urls = TableCell(str(CON.targetobject.abuse_ch_ransomware_urls), bgcolor='green')
                        else:
                            abuse_rsw_urls = TableCell(str(CON.targetobject.abuse_ch_ransomware_urls), bgcolor='red')

                        if (CON.targetobject.abuse_ch_ransomware_ips == False):
                            abuse_rsw_ips = TableCell(str(CON.targetobject.abuse_ch_ransomware_ips), bgcolor='green')
                        else:
                            abuse_rsw_ips = TableCell(str(CON.targetobject.abuse_ch_ransomware_ips), bgcolor='red')  

                        if (CON.targetobject.VT == False):
                            VT = TableCell(str(CON.targetobject.VT), bgcolor='green')
                        else:
                            VT = TableCell(str(CON.targetobject.VT), bgcolor='red') 

                        if (CON.targetobject.xforce == False):
                            xforce = TableCell(str(CON.targetobject.xforce), bgcolor='green')
                        else:
                            xforce = TableCell(str(CON.targetobject.xforce), bgcolor='red') 

                        TB.rows.append([target_link, alexa, abuse_rsw_domains, abuse_rsw_urls, abuse_rsw_ips, VT, xforce])
                    elif ((CON.type == 'info') and (CON.modules!='all')):
                        if (CON.modules == 'alexa'):
                            if (CON.targetobject.alexa == False):
                                alexa = TableCell(str(CON.targetobject.alexa), bgcolor='red')
                            else:
                                alexa = TableCell(str(CON.targetobject.alexa), bgcolor='green')

                            TB.rows.append([target_link, alexa])
                        elif (CON.modules=='abuse_ch_ransomware_domains'):
                            if (CON.targetobject.abuse_ch_ransomware_domains == False):
                                abuse_rsw_domains = TableCell(str(CON.targetobject.abuse_ch_ransomware_domains), bgcolor='green')
                            else:
                                abuse_rsw_domains = TableCell(str(CON.targetobject.abuse_ch_ransomware_domains), bgcolor='red')

                            TB.rows.append([target_link, abuse_rsw_domains])
                        elif (CON.modules=='abuse_ch_ransomware_urls'):
                            if (CON.targetobject.abuse_ch_ransomware_urls == False):
                                abuse_rsw_urls = TableCell(str(CON.targetobject.abuse_ch_ransomware_urls), bgcolor='green')
                            else:
                                abuse_rsw_urls = TableCell(str(CON.targetobject.abuse_ch_ransomware_urls), bgcolor='red')

                            TB.rows.append([target_link, abuse_rsw_urls])
                        elif (CON.modules=='abuse_ch_ransomware_ips'):
                            if (CON.targetobject.abuse_ch_ransomware_ips == False):
                                abuse_rsw_ips = TableCell(str(CON.targetobject.abuse_ch_ransomware_ips), bgcolor='green')
                            else:
                                abuse_rsw_ips = TableCell(str(CON.targetobject.abuse_ch_ransomware_ips), bgcolor='red') 

                            TB.rows.append([target_link, abuse_rsw_ips]) 
                        elif (CON.modules=='VTReputation'):
                            if (CON.targetobject.VT == False):
                                VT = TableCell(str(CON.targetobject.VT), bgcolor='green')
                            else:
                                VT = TableCell(str(CON.targetobject.VT), bgcolor='red') 

                            TB.rows.append([target_link, VT])
                        elif (CON.modules=='XForceReputation'):
                            if (CON.targetobject.xforce == False):
                                xforce = TableCell(str(CON.targetobject.xforce), bgcolor='green')
                            else:
                                xforce = TableCell(str(CON.targetobject.xforce), bgcolor='red')

                            TB.rows.append([target_link, xforce]) 
                        else:                           
                            TB.rows.append([target_link])
                    else:
                        TB.rows.append([target_link])

                del CON.targetobject
                if (CON.targetdealtwith == False):
                    if (Count != numberOfTargets):
                        print '[*] Sleeping 7 seconds before next request...'
                        print '*' * 100
                        time.sleep(7)
                else:
                    CON.targetdealtwith = False

            if (CON.logging == True):
                newlogentry = str(TB)
                REP.WriteReport(CON.reportdir, newlogentry)
                newlogentry = '<br/>Report Complete<br/>'
                REP.WriteReport(CON.reportdir, newlogentry)
                newlogentry = ''
                REP.ReportFooter(CON.reportdir)    
    
        if (CON.debug==True):
	    print '[*] Program Complete'        

        Terminate(0)
'''
END OF LINE
'''
