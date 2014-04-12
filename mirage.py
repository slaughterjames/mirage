#!/usr/bin/python
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
mirage.py - This is the main file of the program and is the jumping off point
into the rest of the code
'''

#python imports
import sys
import os
import subprocess
import re
import urllib
from array import *

#programmer generated imports
from argparser import argparser
from logreader import logreader
from fileio import fileio

'''
Usage()
Function: Display the usage parameters when called
'''
def Usage():
    print 'Usage: [required] --target [optional] --supresswget --supressnmap --supresscert --debug --help'
    print 'Required Arguments:'
    print '--target[can be domain(without http://) or IP] - the host you are investigating.'
    print 'Optional Arguments:'
    print '--url - the full address of the resource you are investigating.'
    print '--supresswget - will not attempt a WGET against the target.'
    print '--supressnmap - will not perform a port scan against the target.  Will automatically' 
    print 'suspend --supresswget and --supresscert as well.'
    print '--supresscert - will not try to pull certificate data from any SSL enabled HTTP port.'
    print '--debug - prints verbose logging to the screen to troubleshoot issues with a recon installation.'
    print '--help - You\'re looking at it!'
    sys.exit(-1)

'''
NMapLogProcess()
Function: Reads in the generated NMap log file and
processes it
'''
def NMapLogProcess():
    LG.NMapRead(AP.nmap_filename, AP.debug)


'''
Whois()
Function: Execute a whois against the provided domain
'''
def Whois(target, logdir):
    FI = fileio()
    filename = logdir + 'Whois.txt'

    if (AP.debug == True):
        print 'Whois domain: ' + target
         
    subproc = subprocess.Popen('whois ' + target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for whois_data in subproc.stdout.readlines():
        AP.whois_output_data += whois_data
        if  (AP.debug == True):
            print whois_data

    FI.WriteFile(filename, AP.whois_output_data)


'''
NMap()
Function: Execute an NMap against the provided target
'''
def NMap(target, logdir):
    FI = fileio()
    AP.nmap_filename = logdir + 'NMap.txt'

    if (AP.debug == True):
        print 'NMap target: ' + target + '\n'

    print 'Starting NMap process.  Please be patient, this could take a few minutes!\n'

    #NMap flags: -A Enable OS detection, version detection, script scanning, and traceroute
    #            -sV Probe open ports to determine service/version info   

    subproc = subprocess.Popen('nmap -A -sV '+target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for nmap_data in subproc.stdout.readlines():
        AP.nmap_output_data += nmap_data
        if (AP.debug == True):
            print nmap_data

    FI.WriteFile(AP.nmap_filename, AP.nmap_output_data)

'''
LinkParser()
Function: Parse a page from the WGet proc and grab any links within.
'''
def LinkParser(port, logdir):

    FI = fileio()
    filename = logdir + 'linkparser_port' + str(port) + '.txt'

    #REGEX
    URL_RE = r"""(?i)\b((?:(https?|ftp)://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?]))"""
    URL_PATTERN = re.compile(URL_RE, re.VERBOSE | re.MULTILINE)

    unique_urls = ''

    for match_data in URL_PATTERN.findall(LG.html_reader_data):
        unique_urls += str(tuple(match_data))
        unique_urls += '\n'         
        if (AP.debug == True):
            print match_data

    FI.WriteFile(filename, unique_urls)

    LG.html_reader_data = ''

'''
Cert()
Function: Grab any certs used on the target   
'''
def Cert(target, logdir): 

    for port in LG.https_data:
        if (AP.debug == True):
             print 'Port: ' + str(port) + '\n'

        FI = fileio()
        filename = logdir + 'certdata_port' + str(port) + '.txt'
        cert_data = ''

        #OpenSSL flags: s_client Implements a generic SSL/TLS client which connects to a remote host using SSL/TLS.
        #               -showcerts Display the whole server certificate chain.
        #               -connect This specifies the host and optional port to connect to.

        subproc = subprocess.Popen('openssl s_client -showcerts -connect ' + target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for cert_data in subproc.stdout.readlines():
            AP.cert_output_data += cert_data
            if (AP.debug == True):
                print cert_data

        FI.WriteFile(filename, AP.cert_output_data)     

'''
WGet()
Function: Execute a WGet against the provided target
'''
def WGet(target, logdir, url):

    if (url != ''):
        #WGet flags: --tries=1 Limit tries to a host connection to 1.
        #            -S Show the original server headers.
        #            --no-check-certificate Will not balk when a site's certificate doesn't match the target domain.
        #            --save-headers Save the server headers for investigation.
        #            -m mirror the contents of the URL given
        #            --no-parent does not download the contents of the entire domain and sub-domains
        #            --directory-prefix output to given directory.    
        if (AP.debug == True):
            print 'wget --tries=1 -S --no-check-certificate --save-headers -m --no-parent --directory-prefix ' + logdir + ' ' + url

        subproc = subprocess.Popen('wget --tries=1 -S --no-check-certificate --save-headers -m --no-parent --directory-prefix ' + logdir + ' ' + url, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for wget_url_data in subproc.stdout.readlines():
            AP.wget_url_output_data += wget_url_data
            if (AP.debug == True):
                print wget_url_data


    for port in LG.http_data:
        if (AP.debug == True):
             print 'Port: ' + str(port) + '\n'

        filename = logdir + 'index_port' + str(port) + '.html'
        log = logdir + 'index_port' + str(port) + '.log'

        if (AP.useragent.find('default') != -1 ):
            if (AP.debug == True):
                print 'wget --tries=1 -S --no-check-certificate --save-headers -O ' + filename + ' ' + target + ':' + str(port)

            #WGet flags: --tries=1 Limit tries to a host connection to 1.
            #            -S Show the original server headers.
            #            --no-check-certificate Will not balk when a site's certificate doesn't match the target domain.
            #            --save-headers Save the server headers for investigation.
            #            -O output to given filename.

            subproc = subprocess.Popen('wget --tries=1 -S --no-check-certificate --save-headers -O ' + filename + ' ' + target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for wget_data in subproc.stdout.readlines():
                AP.wget_output_data += wget_data
                if (AP.debug == True):
                    print wget_data

        else:
            if (AP.debug == True):
                print 'wget --user-agent=' + AP.useragent + ' --tries=1 -S --no-check-certificate --save-headers -O ' + filename + ' ' + target + ':' + str(port)

            #WGet flags: --tries=1 Limit tries to a host connection to 1.
            #            -S Show the original server headers.
            #            --user-agent Will identify as a browser agent and not WGet
            #            --no-check-certificate Will not balk when a site's certificate doesn't match the target domain.
            #            --save-headers Save the server headers for investigation.
            #            -O output to given filename.

            subproc = subprocess.Popen('wget --user-agent=' + AP.useragent + ' --tries=1 -S --no-check-certificate --save-headers -O ' + filename + ' ' + target + ':' + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for wget_data in subproc.stdout.readlines():
                AP.wget_output_data += wget_data
                if (AP.debug == True):
                    print wget_data


        LG.HTMLRead(filename, AP.debug)

        LinkParser(port, logdir)

        filename = ''    
'''
Terminate()
Function: - Attempts to exit the program cleanly when called  
'''
     
def Terminate(exitcode):
    sys.exit(exitcode)

'''
This is the mainline section of the program and makes calls to the 
various other sections of the code
'''

if __name__ == '__main__':
    
        ret = 0
                    
        AP = argparser()
        ret = AP.Parse(sys.argv)
        
        if ret == -1:
            Usage()
            Terminate(ret)
            
        LG = logreader()
        LG.ConfRead(AP.debug)
        AP.logdir = LG.logdir
        
        if (len(LG.logdir) < 4):
            print 'The log directory has not been configured.  Please edit the mirage.conf file before continuing.'
            print ''
            Terminate(-1)
        elif (LG.logdir == '<log directory>'):
            print 'The log directory has not been configured.  Please edit the mirage.conf file before continuing.'
            print ''
            Terminate(-1)
        else:
            AP.logdir = LG.logdir.rstrip('\n')
                    
        logdir = AP.logdir + AP.target + '/'
        if (AP.debug == True):
            print 'logdir: ' + AP.logdir + AP.target
            print ''            
        if not os.path.exists(logdir):
            os.makedirs(logdir)
            Whois(AP.target, logdir)
            if (AP.supressnmap == False):
                NMap(AP.target, logdir)
                NMapLogProcess()
                if (AP.supresscert == False):
                    Cert(AP.target, logdir)
                else:
                    if (AP.debug == True):
                        print 'Certificate data collection supressed this run.'
                if (AP.supresswget == False):
                    WGet(AP.target, logdir, AP.url)
                else:
                    if (AP.debug == True):
                        print 'WGet Collection supressed this run.'
            else:
                if (AP.debug == True):
                    print 'NMap collection supressed this run.  Certificate data collection and WGet collection are dependant on NMap and will therefore be supressed as well.'
        else:
            print AP.target + ': IP has previously been dealt with.  Please check data in: ' + logdir

        if ret == 1:
            Terminate(-1)
        else:
            print 'Program Complete'
            Terminate(0)
