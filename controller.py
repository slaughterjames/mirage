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
controller.py - This file is responsible for keeping global settings available through class properties
'''

#python imports
from array import *

#programmer generated imports
from logger import logger

'''
controller
Class: This class is is responsible for keeping global settings available through class properties
'''
class controller:
    '''
    Constructor
    '''
    def __init__(self):
        self.debug = False
        self.type = []#input from the --type cmd line flag
        self.types = []#list of types read from the config file "addintypes" line
        self.modules = []#input from the --modules cmd line flag 
        self.module_manifest = []#list of all modules available to mirage
        self.modulesdir = ''#Directory where modules are stored.  Set in the static.conf file.
        self.scrapedobject = ''
        self.url = False#Boolean input from the --url cmd line flag 
        self.ip = False#Boolean input from the --ip cmd line flag
        self.ipaddress = ''
        self.domain = False#Boolean input from the --domain cmd line flag 
        self.target = ''#input from the --target cmd line flag denoting single target to investigate
        self.targetlist = ''#input from the --targetlist cmd line flag denoting a list of targets to be read in
        self.targetlistsize = 0#Size[number of entries, not bytes] of the targetlist once read in
        self.listoftargets = []#List object holding the targetlist once read in
        self.singletarget = False#Boolean flag is True if there is only a single target from using --target cmd line flag
        self.targetobject = ''#Object to hold target details to be passed between the main code and the modules
        self.targetdealtwith = False#Boolean operator will be True if a log directory is detected for the current target
        self.sleeptime = ''#Amount of time between analyzing multiple targets
        self.addins = []#list of modules read from the config file "addins" line 
        self.useragent = ''#User-agent string to disguise the nature of the network traffic being used
        self.apikeys = ''
        self.output = ''#input from the --output cmd line flag
        self.nolinksummary = False#Boolean input from the --nolinksummary cmd line flag
        self.csv = False#Boolean input from the --csv cmd line flag 
        self.csv_filename = ''#If CSV output is enabled, the name for said file
        self.csv_line = ''#Ships back and forth with the targetobject and is the CSV output line for the target 
        self.logroot = ''#Directory name read from the config file "logroot" line.  Root directory for all logs
        self.logdir = ''#Full log path where program output will be deposited
        self.reportdir = ''#Root directory when multiple targets are being investigated
        self.logger = ''#Boolean value read from the config file "logger" line.
        self.logging = False#Boolean value when True allows logging output
        self.listmodules = False#Boolean input from the --listmodules cmd line flag
        self.listaddintypes = False#Boolean input from the --listaddintypes cmd line flag
        self.listapikeys = False#Boolean input from the --listapikeys cmd line flag
        self.updatefeeds = False#Boolean input from the --updatefeeds cmd line flag