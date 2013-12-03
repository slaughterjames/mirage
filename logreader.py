'''
mirage v0.1 - Copyright 2013 James Slaughter,
This file is part of mirage v0.1.

mirage v0.1 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.


mirage v0.1 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with mirage v0.1.  If not, see <http://www.gnu.org/licenses/>.
'''


'''
logreader.py - This file is responsible for providing a mechanism to read 
the /var/log/auth.log file 
'''


#No python imports
from array import *

#Programmer generated imports
from fileio import fileio

'''
logreader
Class:  This class is responsible for providing a mechanism to read
the mirage config file as well as the generated NMap and HTML index files.
'''

class logreader:

    '''
    Constructor
    '''
    def __init__(self):
        
        self.logdir = ''
        self.confname = '/etc/mirage/mirage.conf'
        self.http_data = array('i')
        self.https_data = array('i')
        self.html_reader_data = ''

    '''
    ConfRead()
    Function: - Reads in the mirage.conf config file
       
    '''
    def ConfRead(self, debug):
        FConf = fileio()
        FConf.ReadFile(self.confname)
        for line in FConf.fileobject:
            if (debug == True):
                print line
            intLen = len(line)
            if (line.find('logdir') != -1):                
                self.logdir = line[7:intLen]
            else:
                if (debug == True): 
                    print ''
        
        if (debug == True):    
            print 'Finished configuration.'
            print ''
            
    '''
    NMapRead()
    Function: - Reads in the generated NMap file
              - Looks for two specific items on each line from which to pull information on an http/https port
       
    '''
    def NMapRead(self, filename, debug):
        FLog = fileio()
        FLog.ReadFile(filename)
        tmpport = ''
        for line in FLog.fileobject:
            if (line.find('ssl/http') != -1):
                intFromVal1 = line.find('/')
                if ((intFromVal1 != -1) and (intFromVal1 <7)):
                    tmpport = line[0:intFromVal1]
                    self.https_data.append(int(tmpport))
                    self.http_data.append(int(tmpport))
                    if (debug == True):
                        print 'Port: ' + tmpport
                    else:
                        if (debug == True):
                            print ''
                    
                    tmpport = ''
            else:
                if (line.find('http') != -1):
                    intFromVal1 = line.find('/')
                    if ((intFromVal1 != -1) and (intFromVal1 <7)):
                        tmpport = line[0:intFromVal1]
                        self.http_data.append(int(tmpport))
                        if (debug == True):
                            print 'Port: ' + tmpport
                        else:
                            if (debug == True):
                                print ''                            
                        
                        tmpport = ''

        return 0


    '''
    HTMLRead()
    Function: - Reads in the generated HTML index files
              - 
    '''
    def HTMLRead(self, filename, debug):
        FLog = fileio()
        FLog.ReadFile(filename)
        
        for line in FLog.fileobject:
            self.html_reader_data += line
            if (debug == True):
                print line 

        return 0 
