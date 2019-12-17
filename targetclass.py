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
targetclass.py - This file is responsible for the parsing of input data from the command line
               from a user and then populating the appropriate values for use elsewhere in 
               the code
'''

#python imports
from array import *

#programmer generated imports


'''
peclass
Class: This class is responsible for the parsing of input data from the command line
from a user and then populating the appropriate values for use elsewhere in the code
'''
class targetclass:
    '''
    Constructor
    '''
    def __init__(self, logging, csv_line, debug, url, ip, domain, target, useragent):

        self.url = url
        self.ip = ip
        self.domain = domain
        self.target = target   
        self.useragent = useragent
        self.logdir = ''
        self.logging = False
        self.debug = False
        self.http_data = array('i')
        self.https_data = array('i')

        self.logging = logging
        self.csv_line = csv_line
        self.debug = debug
        self.url = url
        self.ip = ip
        self.domain = domain
        self.target = target
        self.useragent = useragent
                     
