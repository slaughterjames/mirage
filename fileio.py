'''
Mirage v0.9 - Copyright 2020 James Slaughter,
This file is part of Mirage v0.9.

Mirage v0.9 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Mirage v0.9 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Mirage v0.9.  If not, see <http://www.gnu.org/license>.
'''

'''
fileio.py - This file is responsible for providing a mechanism to read and 
            write files to and from the hard drive


fileio
Class: This class is responsible for providing a mechanism to read and 
       write files to and from the hard drive
       - Uncomment commented lines in the event troubleshooting is required
'''
class fileio:
    
    '''
    Constructor
    '''
    def __init__(self):
        
        self.fileobject = 0
        

    '''
    ReadFile()
    Function: - Reads a file instructed by the user
              - Saves the data to an object
              - Returns to the caller 
    '''      
    def ReadFile(self, filename):  
        
        try:
            #print ('Opening file: ' + filename + '...')
            error = 'Opening file'
            fin = open(filename, 'r')
        
            #print ('Reading file...')
            error = 'Reading file'
            self.fileobject = fin.readlines()
        
            #print ('Closing file...')
            error = 'Closing file'
            fin.close()
        
            return 0
        
        except:
            print ('[x] Unable to complete operation: %s %s' %(error,filename))
            return -1        
        
    '''    
    WriteNewLogFile()
    Function: - Opens a new file
              - Writes a file instructed by the user            
              - Returns to the caller
    '''    
    def WriteNewLogFile(self, filename, data):
 
        try:   
            #print ('Opening file: ' + filename + '...')
            error = 'Opening file'
            fout = open(filename, "w")
        
            #print ('Writing file...')
            error = 'Writing file'
            fout.write(data)

            #print ('Closing file...')
            error = 'Closing file'
            fout.close() 
        
            return 0
        
        except:
            print ('[x] Unable to complete operation: %s %s' %(error,filename))
            return -1    
        
    '''    
    WriteLogFile()
    Function: - Opens log file
              - Writes to a file instructed by the user            
              - Returns to the caller
    '''    
    def WriteLogFile(self, filename, data):
 
        try:   
            #print ('Opening file: ' + filename + '...')
            error = 'Opening file'
            fout = open(filename, "a")
        
            #print ('Writing file...')
            error = 'Writing file'
            fout.write(data)

            #print ('Closing file...')
            error = 'Closing file'
            fout.close() 
        
            return 0
        
        except:
            print ('[x] Unable to complete operation: %s %s' %(error,filename))
            return -1     
