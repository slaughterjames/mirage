'''
Module Management System Class (MMS) - Copyright 2019 James Slaughter,
This file is part of MMS v0.1.

MMS v0.1 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

MMS v0.1 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with MMS v0.1.  If not, see <http://www.gnu.org/licenses/>.
'''

'''
Usage:
Import:
from mms import mms

Example to initialize the class:
MMS = mms(<list of modules>, <modules directory>, <module to be used>, <Debug True or False>)

Example to execute a module:
ret = 0
ret = MMS.OrganizeModules(<object containing information necessary to execute the module>) 
'''

'''
MMS.py - This class is responsible for the dynamic loading of modules
'''

#python imports
import imp
import sys
from array import *

#programmer generated imports


'''
mms
Class: This class is responsible for the dynamic loading of modules
'''
class mms:
    '''
    Constructor
    '''
    def __init__(self, listofmodules, modulesdir, modules, debug):
    #def __init__(self):

        self.debug = False
        self.modulesdir = ''
        self.modules = ''
        self.listofmodules = []

        self.listofmodules = listofmodules
        self.modulesdir = modulesdir
        self.modules = modules
        self.debug = debug
        
    '''       
    ExecuteModules()
    Function: - takes module name from Organize modules and then tries to find and load it
    '''    
    def ExecuteModules(self, modules, POE):        
        option = ''
        mymod = ''

        if (self.debug == True):
            print '[DEBUG] Modules Directory: ' + self.modulesdir.strip()
      
        #Locate the dynamic module, create a file object for it
        try:
            fp, pathname, description = imp.find_module(modules, [self.modulesdir.strip()])            
            if (self.debug == True):
                print '\n[DEBUG] Module ' + modules + ' located'
                print '\n[DEBUG] fp: ' + str(fp) + ' pathname: ' + str(pathname) + ' description: ' + str(description) + '\n'   
        except ImportError:
            print '\n[x] Unable to locate module: ' + modules
            return -1

        #Load the module into memory
    	try:
            mymod = imp.load_module(modules, fp, pathname, description)
            if (self.debug == True):
                print '[DEBUG] Module ' + modules + ' loaded successfully'
        except Exception, e:
            print '\n[x] Unable to load module: ' + modules + ' -', e
            return -1
        finally:
            fp.close()  

        #Execute the module
        try:
            if (self.debug == True):
                print '[DEBUG] Executing module\n'
            mymod.POE(POE)
        except Exception, e:
            print '\n[x] Unable to execute module: ' + modules + ' -', e  
            return -1
                                         
        return 0


    '''       
    OrganizeModules()
    Function: - Cycles through the arrays of available modules
              - Sends the chosen one on to execution
    ''' 
    def OrganizeModules(self, POE):
        ret = 0

        print '[-] Organize Modules...'

        if (self.modules == 'all'):
            for module_data in self.listofmodules:                
                if (self.debug == True):
                    print '[DEBUG] ' +  ': ' + module_data    
                ret = self.ExecuteModules(module_data.strip(), POE)
        else:
            print '[*] Module ' + self.modules
            ret = self.ExecuteModules(self.modules, POE)

        return ret
        
'''
END OF LINE
'''
