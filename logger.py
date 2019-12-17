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
logger.py - This file is responsible for providing a mechanism to write 
log files to the hard drive and read in the static.conf file


logger
Class: This class is responsible for providing a mechanism to write
       log files to the hard drive and read in the static.conf file
       - Uncomment commented lines in the event troubleshooting is required
        
'''

#python imports
import sys
import os
import datetime

#programmer generated imports
from fileio import fileio

class logger:
    
    '''
    Constructor
    '''
    def __init__(self):
        
        self.startdatetime = ''  

    '''
    ReportCreate()
    Function: - Creates a new log file based on the target
              - Adds a header to the log 
    '''     
    def ReportCreate(self, logdir, targetlist):  
        logroot = logdir + 'logroot.html'
        FLog = fileio()
        
        self.startdatetime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
        filename = logroot

        data = '<html>\n'
        data += '\n--------------------------------------------------------------------------------'
        data += '---------------------------------------<br/>'
        data += '<head>\n<title>'+ '</title>\n'
        data += '\n<strong>Starting Analysis On Targetlist: ' + str(targetlist) + '</strong>' + '\n' 
        data += '\n<br/><strong>Date/Time: </strong>' + self.startdatetime + '<br/>\n'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------<br/>\n</head>\n'
        data += '<link rel=\"stylesheet\" href=\"/opt/mirage/mirage.css\">\n<body>\n'
        FLog.WriteNewLogFile(filename, data)
   
        return 0 

    '''

    ReportFooter()
    Function: - Adds a footer to close out the log file created in the function above
              - 
              -  
    '''     
    def ReportFooter(self, logdir):  
        FLog = fileio()        
        filename = logdir + 'logroot.html'        
        data = '<strong>END OF FILE</strong><br/>'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------\n<br/>'
        data += 'Processed by Mirage v0.8\n<br/>'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------\n<br/>'
        data += '\n</body>\n</html>\n'
        FLog.WriteLogFile(filename, data)
        print '\n'
        print '[*] Report file written to: ' + filename
           
        return 0

    '''    
    WriteReport()
    Function: - Writes to the current log file            
              - Returns to the caller
    '''    
    def WriteReport(self, logdir, newlogline):  
        FLog = fileio()
        filename = logdir + 'logroot.html'
        data = str(newlogline) #+ '\n<br/>'
        FLog.WriteLogFile(filename, data)
           
        return 0 

    '''
    LogCreate()
    Function: - Creates a new log file based on the target
              - Adds a header to the log                
    '''     
    def LogCreate(self, logdir, target):  
        logroot = logdir + 'logroot.html'
        FLog = fileio()
        
        self.startdatetime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
        filename = logdir + target + '.html'
        data = '<html>\n'
        data += '\n--------------------------------------------------------------------------------'
        data += '---------------------------------------<br/>'
        data += '<head>\n<title>' + filename + '</title>\n'
        data += '\n<strong>Starting Analysis On Target: ' + target + '</strong>' + '\n' 
        data += '\n<br/><strong>Date/Time: </strong>' + self.startdatetime + '<br/>\n'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------<br/>\n</head>\n'
        data += '<link rel=\"stylesheet\" href=\"/opt/mirage/mirage.css\">\n<body>\n'
        FLog.WriteNewLogFile(filename, data)
           
        return 0   
    
    '''
    LogFooter()
    Function: - Adds a footer to close out the log file created in the function above
    '''     
    def LogFooter(self, logdir, target):  
        FLog = fileio()        
        filename = logdir + target + '.html'        
        data = '--------------------------------------------------------------------------------'
        data += '---------------------------------------\n<br/>'
        data += 'Processed by Mirage v0.8\n<br/>'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------\n<br/>'
        data += '\n</body>\n</html>\n'
        FLog.WriteLogFile(filename, data)
        print '[*] Log file written to: ' + filename
           
        return 0       
        
    '''    
    WriteLog()
    Function: - Writes to the current log file            
              - Returns to the caller
    '''    
    def WriteLog(self, logdir, target, newlogline):  
        FLog = fileio()
        filename = logdir + target + '.html'
        data = newlogline + '\n<br/>'
        FLog.WriteLogFile(filename, data)
           
        return 0 
