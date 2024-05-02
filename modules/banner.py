#python imports
import sys
import os
import requests
from termcolor import colored

#third-party imports
#Put andy third-party imports here

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Type: Passive/Active - Description: Attempts to pull the banner from a target.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    server_header = ''
    response_code = ''
    output = POE.logdir + 'banner_'

    if (POE.logging == True):
        newlogentry = 'Module: banner'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)    

    if (len(POE.https_data) > 0):
        for port in POE.https_data: 
            print ('\r\n[*] Running banner against: ' + POE.target + ':' + str(port))            
            try:
                # Attempt to get the server header
                response = requests.get('https://' + POE.target + ':' + str(port), verify=False)
                response_code = response.status_code()
                if (POE.debug == True):
                    print ('[DEBUG] Response Code: ' + str(response_code))                
                server_header = response.headers.get('Server', 'No Server Header Found')
                print('[-] Response Code: ' + str(response_code) + ' Server Header: - port ' + str(port) + ': ' + server_header)
                if (POE.logging == True):
                    newlogentry = 'Server Header - port ' + str(port) + ': ' + server_header
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            except Exception as e:
                print(colored('[x] Error fetching data from ' + POE.target + ':' + str(port) + ': ' + str(e)))
                response_code = response.status_code()
                if (POE.debug == True):
                    print ('[DEBUG] Response Code: ' + str(response_code))                
                server_header = response.headers.get('Server', 'No Server Header Found')
                print('[-] Response Code: ' + str(response_code) + ' Server Header: - port ' + str(port) + ': ' + server_header)
                if (POE.logging == True):
                    newlogentry = 'Server Header - port ' + str(port) + ': ' + server_header
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)                
    else:        
        try:
            print ('\r\n[*] Running banner against: ' + POE.target)
            # Attempt to get the server header
            response = requests.get('https://' + POE.target, verify=False)
            response_code = response.status_code()
            if (POE.debug == True):
                print ('[DEBUG] Response Code: ' + str(response_code))                
            server_header = response.headers.get('Server', 'No Server Header Found')
            print('[-] Response Code: ' + str(response_code) + ' Server Header: - port ' + str(port) + ': ' + server_header)
            if (POE.logging == True):
                newlogentry = 'Server Header - port ' + str(port) + ': ' + server_header
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
        except Exception as e:
            print(colored('[x] Error fetching data from ' + POE.target + ': ' + str(e)))        
    
    if (len(POE.http_data) > 0):        
        for port in POE.http_data:             
            print ('\r\n[*] Running banner against: ' + POE.target + ':' + str(port))
            try:
                # Attempt to get the server header
                response = requests.get('http://' + POE.target + ':' + str(port))
                response_code = response.status_code()
                if (POE.debug == True):
                    print ('[DEBUG] Response Code: ' + str(response_code))                
                server_header = response.headers.get('Server', 'No Server Header Found')
                print('[-] Response Code: ' + str(response_code) + ' Server Header: - port ' + str(port) + ': ' + server_header)
                if (POE.logging == True):
                    newlogentry = 'Server Header - port ' + str(port) + ': ' + server_header
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            except Exception as e:
                print(colored('[x] Error fetching data from ' + POE.target + ':' + str(port) + ': ' + str(e)))
    else:
        try:
            print ('\r\n[*] Running banner against: ' + POE.target)
            # Attempt to get the server header
            response = requests.get('http://' + POE.target)
            response_code = response.status_code()
            if (POE.debug == True):
                print ('[DEBUG] Response Code: ' + str(response_code))                
            server_header = response.headers.get('Server', 'No Server Header Found')
            print('[-] Response Code: ' + str(response_code) + ' Server Header: - port ' + str(port) + ': ' + server_header)
            if (POE.logging == True):
                newlogentry = 'Server Header - port ' + str(port) + ': ' + server_header
                LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)           
        except Exception as e:
            print(colored('[x] Error fetching data from ' + POE.target + ': ' + str(e)))

    if (len(POE.other_data) > 0):     
        for port in POE.other_data: 
            print ('\r\n[*] Running banner against: ' + POE.target + ':' + str(port))            
            try:
                # Attempt to get the server header
                response = requests.get('http://' + POE.target + ':' + str(port))
                response_code = response.status_code()
                if (POE.debug == True):
                    print ('[DEBUG] Response Code: ' + str(response_code))                
                server_header = response.headers.get('Server', 'No Server Header Found')
                print('[-] Response Code: ' + str(response_code) + ' Server Header: - port ' + str(port) + ': ' + server_header)
                if (POE.logging == True):
                    newlogentry = 'Server Header - port ' + str(port) + ': ' + server_header
                    LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
            except Exception as e:
                print(colored('[x] Error fetching data from ' + POE.target + ':' + str(port) + ': ' + str(e)))            

    #Do some stuff

    #if your stuff is true                     
    #    print (colored('[-] Stuff is true.', 'green', attrs=['bold']))
    #    if (POE.logging == True):
    #        newlogentry = 'Stuff is true.'
    #        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
    #        POE.csv_line += 'True,'       
    #If your stuff is false
    #    print (colored('[-] Stuff is false.  This could be bad', 'red', attrs=['bold']))
    #    if (POE.logging == True):
    #        newlogentry = 'Stuff is false. <strong>This could be bad.</strong>'
    #        LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)   
    #        POE.csv_line += 'False,' 
    #    print colored('[x] Stuff not written to file.', 'red', attrs=['bold']

    #Unless there is an exception, always return 0 upon completion.
    return 0
