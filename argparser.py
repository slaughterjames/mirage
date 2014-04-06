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
argparser.py - This file is responsible for the parsing of input data from the command line
               from a user and then populating the appropriate values for use elsewhere in 
               the code
'''

#No python imports

#No programmer imports

'''
argparser
Class: This class is responsible for the parsing of input data from the command line
from a user and then populating the appropriate values for use elsewhere in the code
'''
class argparser:
    '''
    Constructor
    '''
    def __init__(self):

        self.target = ''
        self.url = ''
        self.supresswget = False
        self.supresscert = False
        self.supressnmap = False
        self.logdir = ''
        self.whois_output_data = ''
        self.nmap_filename = ''
        self.nmap_output_data = ''
        self.wget_output_data = ''
        self.wget_url_output_data = ''
        self.cert_output_data = ''
        self.useragent = ''
        self.debug = False
        
        
    '''       
    Parse()
    Function: - Determines if all required arguments are present
              - Populates the required variables               
    '''    
    def Parse(self, args):        
        option = ' '
        
        if len(args) < 3:        
            print 'Insufficient number of arguments.'
            print ''
            return -1
         
        print 'Arguments: '
        for i in range(len(args)):
            if args[i].startswith('--'):
                option = args[i][2:]
                
                if option == 'help':
                    return -1

                if option == 'target':
                    self.target = args[i+1] 
                    print option + ': ' + self.target

                if option == 'url':
                    self.url = args[i+1]
                    print option + ': ' + self.url

                if option == 'supresswget':
                    self.supresswget = True
                    print option + ': ' + str(self.supresswget)

                if option == 'supressnmap':
                    self.supressnmap = True
                    print option + ': ' + str(self.supressnmap)

                if option == 'supresscert':
                    self.supresscert = True
                    print option + ': ' + str(self.supresscert)

                if option == 'debug':
                    self.debug = True
                    print option + ': ' + str(self.debug)

        print ''                    
       
        if len(self.target) < 7:
            print 'target is a required argument'
            print ''
            return -1
                                
        return 0
