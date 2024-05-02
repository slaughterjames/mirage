'''
Mirage v1.0 - Copyright 2024 James Slaughter,
This file is part of Mirage v1.0.

Mirage v1.0 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Mirage v1.0 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Mirage v1.0.  If not, see <http://www.gnu.org/license>.
'''

'''
portmap.py -   This class is responsible for obtaining port information about a target
               and adding http and https services to the target's object
'''

#python imports
#import sys
#import os
#import subprocess
import json
from termcolor import colored

#third-party imports
import nmap3

#programmer generated imports
from logger import logger
from targetclass import targetclass
from fileio import fileio

'''
portmap
Class: This class is responsible for obtaining port information about a target
       and adding http and https services to the target's object
'''
class portmap:
    '''
    Constructor
    '''
    def __init__(self):
        fn = ''

    '''
    Triage()
    Function: - Function caller
    '''
    def Map(self, POE):

        if (POE.logging == True): 
            LOG = logger()
        newlogentry = ''
        nmap_data = ''

        nmap_output = POE.logdir + 'NMap.json'

        nmap = nmap3.NmapHostDiscovery()        

        if (POE.logging == True):
            newlogentry = 'Module: portmap'           
            LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)
    
        print ('\n\r[*] Running NMap against: ' + POE.target + '\n')
        
        #nmap_data = nmap.nmap_portscan_only(POE.target, args="-sV -F")
        nmap_data = nmap.nmap_portscan_only(POE.target, args="-F")

        result = json.dumps(nmap_data, sort_keys=False, indent=4)        

        if  (POE.debug == True):
            print (result)        

        try:
            with open(nmap_output,'w') as write_file:
                write_file.write(result)
            write_file.close()
            print (colored('[*] NMap data has been written to file here: ', 'green', attrs=['bold']) + colored(nmap_output  + '\n', 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'NMap file has been generated to file here: <a href=\"' + nmap_output + '\"> NMap Output </a>'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        except Exception as e:
            print (colored('[x] Unable to write nmap data to file...' + str(e)  + '\n', 'red', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'Unable to write nmap data to file'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            return POE       

        print ('')

        result = json.loads(result)

        try:
            ip_address = list(result.keys())[0]            
            state_info = result[ip_address]['state']
            ports_info = result[ip_address]['ports']
        except Exception as e:
            print (colored('[x] There doesn\'t appear to be any data for this domain...' + str(e)  + '\n', 'red', attrs=['bold']))
            print ('')
            return POE
        
        POE.ipaddress = ip_address
               
        if ('up' in state_info['state']):
            print (colored('[*] Host appears to be up.\n', 'green', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'Host appears to be up.'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)             
            print(colored('[*] IP Address: ' + str(ip_address)  + '\n', 'green', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'IP Address: ' + str(ip_address)
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)            
        else:
            print (colored('[x] Host seems down.\n', 'red', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'Host seems down.'
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry) 
            print(colored('[*] IP Address: ' + str(ip_address), 'red', attrs=['bold']))            
            if  (POE.debug == True):
                print (state_info['state'])

        for port in ports_info:            
            if  (POE.debug == True):
                print('[DEBUG] Port: ' + str(port['portid']) + '\n')
                print('[DEBUG] State: ' + str(port['state']) + '\n')
                print('[DEBUG] Service: ' + str(port['service']['name']) + '\n')
                print ('')

            if (str(port['service']['name']) == 'https'):
                try:                    
                    if ((not int(port['portid']) in POE.http_data) and (not int(port['portid']) in POE.https_data)):                    
                        POE.https_data.append(int(port['portid']))                    
                    else:
                        print ('[-] Port: ' + str(port['portid']) + ' already added...\n')                                            
                except:
                    print ('[x] Unable to add port to array: ' + str(port['portid']))
            elif ('ssl/http' in str(port['service']['name'])):
                try:
                    if ((not int(port['portid']) in POE.http_data) and (not int(port['portid']) in POE.https_data)):
                        POE.https_data.append(int(port['portid']))
                    else:
                        print ('[-] Port: ' + str(port['portid']) + ' already added...\n')                    
                except:
                    print ('[x] Unable to add port to array: ' + str(port['portid']))
            elif (str(port['service']['name']) == 'http'):
                try:                
                    if ((not int(port['portid']) in POE.http_data)):
                        POE.http_data.append(int(port['portid']))
                    else:
                        print ('[-] Port: ' + str(port['portid']) + ' already added...\n')
                except:
                    print ('[x] Unable to add port to array: ' + str(port['portid']))
            else:                   
                try:                
                    if ((not int(port['portid']) in POE.http_data) and (not int(port['portid']) in POE.https_data) and (not int(port['portid']) in POE.other_data)):
                        POE.other_data.append(int(port['portid']))
                    else:
                        print ('[-] Port: ' + str(port['portid']) + ' already added...\n')
                except:
                    print ('[x] Unable to add port to array: ' + str(port['portid']))

        for port in POE.http_data:
            if (POE.logging == True):
                newlogentry = 'HTTP Port: ' + str(port)
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            if  (POE.debug == True):
                print ('[DEBUG] HTTP Port: ' + str(port))

        for port in POE.https_data:
            if (POE.logging == True):
                newlogentry = 'HTTPS Port: ' + str(port)
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            if  (POE.debug == True):
                print ('[DEBUG] HTTPS Port: ' + str(port))

        for port in POE.other_data:
            if (POE.logging == True):
                newlogentry = 'Other Port: ' + str(port)
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            if  (POE.debug == True):
                print ('[DEBUG] Other Port: ' + str(port))                

        print ('')            
        
        return POE