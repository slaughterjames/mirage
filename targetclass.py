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
along with Mirage v0.9.  If not, see <http://www.gnu.org/license>>
'''

'''
targetclass.py - This file is responsible for the creation of the targetclass
'''

#python imports
from array import *

#programmer generated imports


'''
targetclass
Class: This class is responsible for holding the data for a given target under
       investigation and then populating the appropriate values for use elsewhere 
       in the code
'''
class targetclass:
    '''
    Constructor
    '''
    def __init__(self, logging, csv_line, debug, nolinksummary, url, ip, domain, target, useragent):

        self.url = url
        self.ip = ip
        self.domain = domain
        self.target = target   
        self.useragent = useragent
        self.logdir = ''
        self.logging = False
        self.debug = False
        self.nolinksummary = False
        self.http_data = array('i')
        self.https_data = array('i')

        self.logging = logging
        self.csv_line = csv_line
        self.debug = debug
        self.nolinksummary = nolinksummary
        self.url = url
        self.ip = ip
        self.domain = domain
        self.target = target
        self.useragent = useragent
                     
