#python imports
import sys
import os
import subprocess
from array import *
from termcolor import colored

#third-party imports
from selenium import webdriver

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Passive/Active - Description: Uses the Selenium web driver to take a screenshot of the web site.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True):
        LOG = logger()
    newlogentry = ''
    strings_dump = ''
    strings_output_data = ''
    screenshot_data = ''
    screenshot_output_data = ''
    http_data = []
    https_data = []
    #ports = [80, 443]

    if not POE.http_data:
        print colored('\r\n[-] Screenshot - Active scan not undertaken for HTTP ports.  Defaulting to 80...', 'yellow', attrs=['bold'])
        http_data = [80]
    else:
        http_data = POE.http_data

    if not POE.https_data:
        print colored('\r\n[-] Screenshot - Active scan not undertaken for HTTPs ports.  Defaulting to 443...', 'yellow', attrs=['bold'])
        https_data = [443]
    else:
        http_data = POE.https_data 

    for port in http_data:
        if (POE.debug == True):
            print '[DEBUG] Port: ' + str(port) + '\n'

        output = POE.logdir + POE.target + str(port) + '.png'

        print '\r\n[*] Running Screenshot against: ' + POE.target + ':' + str(port)
        try:
            driver = webdriver.PhantomJS()
            driver.set_window_size(1024, 768) # set the window size that you need
            driver.get('http://' + POE.target)
            driver.save_screenshot(output)
            driver.quit()
            print colored('[*] Screenshot file has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
            if (POE.logging == True):
                newlogentry = 'Screenshot file has been generated to file here: <a href=\"' + output + '\">  Port ' + str(port) + ' Output </a>'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry) 
        except Exception as e:
            print colored('[x] Unable to complete screenshot: ' + str(e), 'red', attrs=['bold'])
            if (POE.logging == True):
                POE.csv_line += 'False,'
            return -1 
            

    for port in https_data:
        if (POE.debug == True):
            print '[DEBUG] Port: ' + str(port) + '\n'

        output = POE.logdir + POE.target + str(port) + '.png'

        print '\r\n[*] Running Screenshot against: ' + POE.target + ':' + str(port) 
        try:
            driver = webdriver.PhantomJS()
            driver.set_window_size(1024, 768) # set the window size that you need
            driver.get('https://' + POE.target)
            driver.save_screenshot(output)
            driver.quit()
            print colored('[*] Screenshot file has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold'])
            if (POE.logging == True):
                newlogentry = 'Screenshot file has been generated to file here: <a href=\"' + output + '\">  Port ' + str(port) + ' Output </a>'
                LOG.WriteLog(POE.logdir, POE.target, newlogentry)
        except Exception as e:
            print colored('[x] Unable to complete screenshot: ' + str(e), 'red', attrs=['bold'])
            if (POE.logging == True):
                POE.csv_line += 'False,'
            return -1 

    if (POE.logging == True):
        POE.csv_line += 'True,'    

    return 0
