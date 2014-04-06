'''
mirage v0.2 - Copyright 2014 James Slaughter,
This file is part of mirage v0.2.

mirage v0.2 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.


mirage v0.2 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with mirage v0.2.  If not, see <http://www.gnu.org/licenses/>.
'''

'''
fileio.py - This file is responsible for providing a mechanism to read and 
            write files to and from the hard drive
'''

#No python imports

#No programmer imports

'''
fileio
Class: This class is responsible for providing a mechanism to read and 
       write files to and from the hard drive
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
            print 'Opening file: ' + filename + '...'
            error = 'Opening file'
            fin = open(filename, 'r')
        
            print 'Reading file...'
            error = 'Reading file'
            self.fileobject = fin.readlines()
        
            print 'Closing file...'
            error = 'Closing file'
            fin.close()
        
            return 0
        
        except:
            print 'Unable to complete operation: %s %s' %(error,filename)
            return -1        
        
    '''    
    WriteFile()
    Function: - Writes a file instructed by the user            
              - Returns to the caller
    '''    
    def WriteFile(self, filename, data):
 
        try:   
            print 'Opening file: ' + filename + '...'
            error = 'Opening file'
            fout = open(filename, "w")
        
            print 'Writing file...'
            error = 'Writing file'
            fout.write(data)

            print 'Closing file...'
            error = 'Closing file'
            fout.close() 
        
            return 0
        
        except:
            print 'Unable to complete operation: %s' %error
            return -1      
