'''
Mirage v0.7 - Copyright 2017 James Slaughter,
This file is part of Mirage v0.7.

Mirage v0.7 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Mirage v0.7 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Mirage v0.7.  If not, see <http://www.gnu.org/licenses/>..
'''

'''
portmap.py -   This class is responsible for obtaining port information about a target
               and adding http and https services to the target's object
'''

#python imports
import sys
import os
import subprocess

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
    def Map(self, target, logging, logdir,  debug):

        if (logging == True): 
            LOG = logger()
        newlogentry = ''
        nmap_data = ''
        nmap_output_data = ''

        nmap_output = logdir + 'NMap.txt'

        FI = fileio()
    
        print '[*] Running NMap against: ' + target.target

        subproc = subprocess.Popen('nmap -A -sV ' + target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for nmap_data in subproc.stdout.readlines():
            nmap_output_data += nmap_data           
            if (nmap_data.find('https') != -1):
                intFromVal1 = nmap_data.find('/')
                if ((intFromVal1 != -1) and (intFromVal1 <7)):
                    tmpport = nmap_data[0:intFromVal1]
                    try:
                        target.https_data.append(int(tmpport))
                        target.http_data.append(int(tmpport))
                    except:
                        print '[x] Unable to add port to array: ' + str(tmpport)          
            elif (nmap_data.find('ssl/http') != -1):
                intFromVal1 = nmap_data.find('/')
                if ((intFromVal1 != -1) and (intFromVal1 <7)):
                    tmpport = nmap_data[0:intFromVal1]
                    try:
                        target.https_data.append(int(tmpport))
                        target.http_data.append(int(tmpport))
                    except:
                        print '[x] Unable to add port to array: ' + str(tmpport)
            else:
                if (nmap_data.find('http') != -1):
                    intFromVal1 = nmap_data.find('/')
                    if ((intFromVal1 != -1) and (intFromVal1 <7)):
                        tmpport = nmap_data[0:intFromVal1]
                        try:
                            target.http_data.append(int(tmpport))
                        except:
                            print '[x] Unable to add port to array: ' + str(tmpport)  

        if  (debug == True):
            print nmap_data    

        try:        
            FI.WriteLogFile(nmap_output, nmap_output_data)
            print '[*] NMap data had been written to file here: ' + nmap_output
            if (logging == True):
                newlogentry = 'NMap file has been generated to file here: <a href=\"' + nmap_output + '\"> NMap Output </a>'
                LOG.WriteLog(logdir, target.target, newlogentry)
        except:
            print '[x] Unable to write nmap data to file' 
            if (logging == True):
                newlogentry = 'Unable to write nmap data to file'
                LOG.WriteLog(logdir, target.target, newlogentry)
            return -1

        return target
