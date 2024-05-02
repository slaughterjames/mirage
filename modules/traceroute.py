#python imports
from termcolor import colored

#third-party imports
from icmplib import ping, multiping, traceroute, resolve, Host, Hop

#programmer generated imports
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: Passive - Description: Executes a traceroute against the target.  *Requires root privileges!!!*
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    trt_output_data = ''
    hops = ''
    last_distance = 0
    output = POE.logdir + 'Traceroute.txt'

    if (POE.logging == True):
        newlogentry = 'Module: traceroute'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    print ('\r\n[*] Running Traceroute against: ' + POE.target)

    try:
        hops = traceroute(POE.target)
    except Exception as e:
        print (colored('[x] Exception executing traceroute: ' + str(e), 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Exception executing traceroute: ' + str(e)
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
            POE.csv_line += 'False,'
        return -1

    trt_output_data += 'Distance/TTL    Address             Average round-trip time\n'
    for hop in hops:
        if ((last_distance + 1) != (hop.distance)):
            print(colored('[-] Some gateways are not responding','yellow', attrs=['bold']))

        # See the Hop class for details
        trt_output_data += str(hop.distance) + '               ' + str(hop.address) + '               ' + str(hop.avg_rtt) + 'ms\n'

        last_distance = hop.distance    

    try:               
        with open(output,'w') as write_file:
            write_file.write(trt_output_data)
        write_file.close()         
        print (colored('[*] Traceroute data has been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Traceroute data has been generated to file here: <a href=\"' + output + '\"> Traceroute Output </a>'
            LOG.WriteSubLog(POE.logdir, POE.target, newlogentry)
    except:
        print (colored('[x] Exception.  Unable to write Traceroute data to file!', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Exception.  Unable to write Traceroute data to file!'
            LOG.WriteStrongSubLog(POE.logdir, POE.target, newlogentry)
        return -1

    return 0