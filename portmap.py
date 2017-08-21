'''
Static v0.1 - Copyright 2017 James Slaughter,
This file is part of Static v0.1.

Static v0.1 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Static v0.1 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Static v0.1.  If not, see <http://www.gnu.org/licenses/>.
'''

'''
FILtriage.py - This file is responsible for obtaining basic information about a target
               file including verifying the file type and gather hashes
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
filetriage
Class: This file is responsible for obtaining basic information about a target
       file including verifying the file type and gather hashes
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

        nmap_data = ''
        nmap_output_data = ''

        nmap_output = logdir + 'NMap.txt'

        FI = fileio()
    
        print '[*] Running NMap against: ' + target.target

        if (logging == True):
            newlogentry = 'Running NMap against: <strong>' + target.target + '</strong>'
            LOG.WriteLog(logdir, target.filename, newlogentry)

        subproc = subprocess.Popen('nmap -A -sV ' + target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for nmap_data in subproc.stdout.readlines():
            nmap_output_data += nmap_data           
            if (nmap_data.find('https') != -1):
                intFromVal1 = nmap_data.find('/')
                if ((intFromVal1 != -1) and (intFromVal1 <7)):
                    tmpport = nmap_data[0:intFromVal1]
                    target.https_data.append(int(tmpport))
                    target.http_data.append(int(tmpport))
            else:
                if (nmap_data.find('http') != -1):
                    intFromVal1 = nmap_data.find('/')
                    if ((intFromVal1 != -1) and (intFromVal1 <7)):
                        tmpport = nmap_data[0:intFromVal1]
                        target.http_data.append(int(tmpport))

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
