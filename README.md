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

Usage: [required] [--ip|--domain|--url] [--target|--targetlist] --type --modules [optional] --sleeptime --url --output --listmodules -updatefeeds --debug --help
Example: /opt/mirage/mirage.py --ip --target 192.168.1.1 --type info --modules all --output /your/directory --debug
Required Arguments:
--ip - the target being investigated is an IP address
OR
--domain - the target being investigated is a domain
OR
--url - the target being investigated is a full URL
--target - single target host to examine
OR
--targetlist - list of hosts to examine in one session
--type - info, passive, active or all
--modules - all or specific
Optional Arguments:
--sleeptime - Choose the sleep period between targets when --targetlist is used.  Default is 7 seconds.  Value must be between 0 and 120.
--output - choose where you wish the output to be directed
--listmodules - prints a list of available modules and their descriptions.
--updatefeeds - update the feeds used for the info type switch.
--debug - prints verbose logging to the screen to troubleshoot issues with a recon installation.
--help - You're looking at it!


DEFAULT MODULE LIST
[*] VTReputation
Retrieves the reputation data for domains and IPs against the VirusTotal database.
[*] ThreatCrowdReputation
Retrieves the reputation data for domains and IPs against the ThreatCrowd database.
[*] XForceReputation
Retrieves the reputation data for domains and IPs against the IBM X-Force Exchange database.
[*] Shodan
Retrieves the available data for targets against the Shodan dataset.
[*] whois
Queries the WhoIs information for a target
[*] alexa
Executes a grep against the top 1 million sites on Alexa.
[*] abuse_ch_ransomware_domains
Executes a grep against the abuse.ch ransomware domains feed.
[*] abuse_ch_ransomware_urls
Executes a grep against the abuse.ch ransomware URLs feed.
[*] abuse_ch_ransomware_ips
Executes a grep against the abuse.ch ransomware IPs feed.
[*] abuse_ch_feodo
Executes a grep against the abuse.ch Feodo IP blocklist feed.
[*] wget
Executes a WGet operation against the target
[*] cert
Pulls the target's certificate data using OpenSSL
[*] dig
Executes Dig against the target.
[*] host
Executes host -a against the target.
[*] nslookup
Executes an NSLookup against the target.
[*] traceroute
Executes a traceroute against the target.

CHANGELOG VERSION V0.5:
- Added changes to some of the modules to increase visibility over malicious findings.
- Fixed issue with the way the --type active flag works.  Now uses dedicated portmap class to feed data for classes built around it.
- Added a --sleeptime flag to allow control over how long mirage sleeps between targets.  Useful when not using one of the API led  modules.
- Added a sleeptime variable to mirage.conf.  Can set for default limit between targets without using the --sleeptime flag.  

CHANGELOG VERSION V0.4:
- Big architectural redesign
- Added the concept of modules so small purpose-built add-ins can be created and integrated quickly
- Information gathering modules pull data from a separate feeds directory.  Contained within is data downloaded from Abuse.ch and Alexa
- Added colored terminal messages to modules to highlight important items.
- Added the concept of a targetlist.  Multiple targets can be entered into a textfile with Mirage reading and executing against each of them (currently limited to targets of the same type - IPs, domains, etc)
- When the targetlist is used, a log file is created for the entire run highlighting which targets are known malicious 

CHANGELOG VERSION V0.3:
Fixed some issues with WGet. The preservation of the headers was causing issues to the file integrity.
Added the ability to run the target domain or ip through VirusTotal's reputation engine if you've signed up and have an API key. If you don't want to use this functionality, leave the mirage.conf setting as default.
In adding the above functionality, you will need to download and install the simplejson package from: https://github.com/simplejson/simplejson

CHANGELOG VERSION v0.2:
- Merged code from PYRecon 0.4 to add a line in the mirage config file to allow WGet to use a browser user-agent string
- Added the --url input arg so wget will mirror and download everything residing at or near a particular web resource.
