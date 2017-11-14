'''
Mirage v0.5 - Copyright 2017 James Slaughter,
This file is part of Mirage v0.5.

Mirage v0.5 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Mirage v0.5 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Mirage v0.5.  If not, see <http://www.gnu.org/licenses/>.
'''

'''
controller.py - This file is responsible for the dynamic loading of static's modules
'''

#python imports
import imp
import sys
from array import *

#programmer generated imports
from logger import logger

'''
controller
Class: This class is responsible for the dynamic loading of static's modules
'''
class controller:
    '''
    Constructor
    '''
    def __init__(self):

        self.debug = False
        self.type = ''
        self.modules = ''
        self.url = False
        self.ip = False
        self.domain = False
        self.target = ''
        self.targetlist = ''
        self.targetlistsize = 0
        self.listoftargets = []
        self.singletarget = False
        self.targetobject = ''
        self.targetdealtwith = False
        self.sleeptime = ''
        self.infoaddins = []
        self.activeaddins = []
        self.passiveaddins = [] 
        self.useragent = ''
        self.apikey = ''
        self.output = ''
        self.logroot = ''
        self.logdir = ''
        self.reportdir = ''
        self.logger = ''
        self.logging = False
        self.listmodules = False
        self.updatefeeds = False
        
    '''       
    ExecuteModules()
    Function: - Determines if all required arguments are present
              - Populates the required variables and determines the protocol if not specified
              - returns to calling fuzzer 
              - Uncomment print items to aid in troubleshooting
    '''    
    def ExecuteModules(self, modules):        
        option = ''
        mymod = ''
      
        #Locate the dynamic module, create a file object for it
        try:
            fp, pathname, description = imp.find_module(modules, [self.modulesdir.strip()])            
            if (self.debug == True):
                print '\n[DEBUG] Module ' + modules + ' located'
                print '\n[DEBUG] fp: ' + str(fp) + ' pathname: ' + str(pathname) + ' description: ' + str(description) + '\n'   
        except ImportError:
            print '[x] Unable to locate module: ' + modules

        #Load the module into memory
    	try:
            mymod = imp.load_module(modules, fp, pathname, description)
            if (self.debug == True):
                print '[DEBUG] Module ' + modules + ' loaded successfully'
        except Exception, e:
            print '[x] Unable to load module: ', e      
        finally:
            fp.close()  

        #Execute the module
        try:
            if (self.debug == True):
                print '[DEBUG] Executing module\n'
            if (self.type == 'info'):
                mymod.POE(self.logdir, self.targetobject, self.logging, self.debug)
            elif (self.type == 'active'):
                mymod.POE(self.logdir, self.targetobject, self.logging, self.debug)
            elif (self.type == 'passive'):
                mymod.POE(self.logdir, self.targetobject, self.logging, self.debug)
            elif (self.type == 'all'):
                mymod.POE(self.logdir, self.targetobject, self.logging, self.debug)
        except Exception, e:
            print '[x] Unable to load module: ', e  
            return -1
                                         
        return 0


    '''       
    OrganizeModules()
    Function: - Cycles through the arrays of available modules
              - Sends the chosen one on to execution
    ''' 
    def OrganizeModules(self):
        print '[*] Organize Modules'

        if ((self.type == 'info') and (self.modules == 'all')):
            for infoaddins_data in self.infoaddins:                
                if (self.debug == True):
                    print '[DEBUG] Information Module: ' + infoaddins_data    
                self.ExecuteModules(infoaddins_data.strip())

        if ((self.type == 'passive') and (self.modules == 'all')):
            for passiveaddins_data in self.passiveaddins:                
                if (self.debug == True):
                    print '[DEBUG] Passive Module: ' + passiveaddins_data    
                self.ExecuteModules(passiveaddins_data.strip())

        if ((self.type == 'active') and (self.modules == 'all')):
            for activeaddins_data in self.activeaddins:
                if  (self.debug == True):
                    print '[DEBUG] Active Module: ' + activeaddins_data    
                self.ExecuteModules(activeaddins_data.strip())

        if ((self.type == 'all') and (self.modules == 'all')):
            for infoaddins_data in self.infoaddins:                
                if (self.debug == True):
                    print '[DEBUG] Information Module: ' + infoaddins_data    
                self.ExecuteModules(infoaddins_data.strip())
            for passiveaddins_data in self.passiveaddins:                
                if (self.debug == True):
                    print '[DEBUG] Passive Module: ' + passiveaddins_data    
                self.ExecuteModules(passiveaddins_data.strip())
            for activeaddins_data in self.activeaddins:
                if  (self.debug == True):
                    print '[DEBUG] Active Module: ' + activeaddins_data    
                self.ExecuteModules(activeaddins_data.strip())

        if (((self.type == 'info') or (self.type == 'passive') or (self.type == 'active')) and (self.modules != 'all')):
            print '[*] Module ' + self.modules
            self.ExecuteModules(self.modules)     

        return 0
        


         

