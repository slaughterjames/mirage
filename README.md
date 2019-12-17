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

Usage: [required] [--ip|--domain|--url] [--target|--targetlist] --type --modules [optional] --sleeptime --url --output --csv --listmodules --listaddintypes --updatefeeds --debug --help
Example: /opt/mirage/mirage.py --ip --target 192.168.1.1 --type "info passive active"--modules all --output /your/directory --debug
Required Arguments:
--ip - The target being investigated is an IP address
OR
--domain - The target being investigated is a domain
OR
--url - The target being investigated is a full URL
--target - Single target host to examine
OR
--targetlist - List of hosts to examine in one session
--type - info, passive, active or all
--modules - all or specific
Optional Arguments:
--sleeptime - Choose the sleep period between targets when --targetlist is used.  Default is 15 seconds.  Value must be between 0 and 120.
--output - Choose where you wish the output to be directed
--csv - Output to csv if logging is enabled
--listmodules - Prints a list of available modules and their descriptions.
--listaddintypes - Prints a list of available addin types as defined in the mirage.conf file.  Defines a group of modules to run.
--updatefeeds - Update the feeds used for the info type switch.
--debug - Prints verbose logging to the screen to troubleshoot issues with a recon installation.
--help - You're looking at it!

DEFAULT ADDIN TYPES
[*] Addin types available are:

[*] Type: active
[*] Type: passive
[*] Type: info
[*] --Or-- type all

DEFAULT MODULE LIST
[*] ThreatCrowdReputation: Type: Info - Description: Retrieves the reputation data for domains and IPs against the ThreatCrowd database.

[*] XForceReputation: Type: Info - Description: Retrieves the reputation data for domains and IPs against the IBM X-Force Exchange database.

[*] URLScanioReputation: Type: Info - Description: Retrieves information from URLScan.io's database.

[*] VTReputation: Type: Info - Description: Retrieves the reputation data for domains and IPs against the VirusTotal database.

[*] FortiguardReputation: Type: Info - Description: Retrieves the categorization data for domains and IPs against Fortiguard's database.

[*] Shodan: Type: Info - Description: Retrieves the available data for targets against the Shodan dataset.

[*] whois: Type: Info - Description: Queries the WhoIs information for a target

[*] tor_node: Type: Info - Description: Executes a grep against the current TorDNSEL list of exit nodes.

[*] abuse_ch_ransomware_ips: Type: Info - Description: Executes a grep against the abuse.ch ransomware IPs feed.

[*] abuse_ch_ransomware_domains: Type: Info - Description: Executes a grep against the abuse.ch ransomware domains feed.

[*] abuse_ch_ransomware_urls: Type: Info - Descripition: Executes a grep against the abuse.ch ransomware URLs feed.

[*] abuse_ch_feodo: Type: Info - Description: Executes a grep against the abuse.ch Feodo IP blocklist feed.

[*] abuse_ch_urlhaus: Type: Info - Description: Executes a grep against the abuse.ch URLHaus blocklist feed.

[*] alexa: Type: Info - Description: Executes a grep against the top 1 million Internet domains on Alexa.

[*] dig: Type: Passive - Description: Executes Dig against the target.

[*] nslookup: Type: Passive - Description: Executes an NSLookup against the target.

[*] host: Type: Passive - Description: Executes host -a against the target.

[*] traceroute: Type: Passive - Description: Executes a traceroute against the target.

[*] wget: Type: Passive/Active - Description: Executes a WGet operation against the target

[*] screenshot: Type: Passive/Active - Description: Uses the Selenium web driver to take a screenshot of the web site.

[*] cert: Type: Active - Description: Pulls the target's certificate data using OpenSSL

CHANGELOG VERSION V0.8:
- Re-wrote nearly the entire code base.
- Improved the portscanning feature.
- Added the MMS (Module Management System Class) to make it easier to create, manage and integrate new addins.
- Removed the existing HTML log overview system and improved the CSV file output to replace it to reduce hardcoding.
- Added a CSS stylesheet to make the log output nicer
- Added screenshot addin.
- Added tor_node addin.
- Added URLScanioReputation addin.
- Removed entropy addin.
- Removed TalosReputation addin.
 

CHANGELOG VERSION V0.7:
- Re-wrote nearly all of the info modules to work better and not write to desk when not necessary.
- Added a module to make a rough calculation of the entropy(random-ness) of a domain. 
- Fixed Bluecoat module so it works again.
- Fixed the ThreatCrowd module so it doesn't return false positive malware results.
- Added info modules for Fortiguard and Talos for IP and domain reputation.

CHANGELOG VERSION V0.6:
- Added --csv flag to allow logging to CSV file.
- Made improvements to several modules so they only execute when the right data set is being sent to them to be more efficient.


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
