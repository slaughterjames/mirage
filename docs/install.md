## Mirage v0.9 - Installation Guide

Mirage has been tested on Ubuntu-based Linux distributions.  It is generally recommended using the the latest available version (or at least the latest long-term supported version).  It is also recognized that the code is primarily based on Python 2.7 which is now EOL.  The next major revision of the code will make the jump to Python3.

## Download the Installation Script

1. Download the Mirage installation script:
```bash
wget https://raw.githubusercontent.com/slaughterjames/mirage/master/get-mirage.sh -O get-mirage.sh
```
2. Grant execution privileges:
```
chmod +x get-mirage.sh
```

## Execute the Script

1. Execute the script:

```bash
sudo ./get-mirage.sh
```

The script will do the heavy lifting of installing the requisite .deb files and Python libraries as well as tucking the program files into the correct directory.

## Test for Failed Installation of Python Libraries

Occasionally, pip doesn't install all of the Python modules for one reason or another.  To test everything was installed, simply try to execute Mirage:

```bash
opt/mirage/mirage.py
```

If there were issues executing the install of the modules, it will turn up here.  To fix, run the following:

```bash
sudo pip install <required python library>
```

## Updating the mirage.conf File

The mirage.conf file contains the configuration information used by Mirage to execute.  It needs a few values up front in order to execute.

1. Use your favourite editor to open the mirage.conf file.  We'll use nano in this example:

```bash
nano /opt/mirage/mirage.conf
```

2. Review default settings:

```bash
{
    "logger": "true",
    "logroot": "<add your log directory>",
    "modulesdir": "/opt/mirage/modules/",
    "useragent": "default",
    "sleeptime": "7",
    "useragent": "default",
    "addintypes": ["active","passive","info"],
    "addins": [
        {
            "info": "ThreatCrowdReputation"
        },
        {
            "info": "XForceReputation"
        },
        {
            "info": "VTIPReport"
        },
        {
            "info": "VTDomainReport"
        },
        {
            "info": "Secureworks"
        },
        {
            "info": "Shodan"
        },
        {
            "info": "whois"
        },
        {
            "info": "tor_node"
        },
        {
            "info": "abuse_ch_ransomware_ips"
        },
        {
            "info": "abuse_ch_ransomware_domains"
        },
        {
            "info": "abuse_ch_ransomware_urls"
        },
        {
            "info": "abuse_ch_feodo"
        },      
        {
            "info": "abuse_ch_urlhaus_host"
        },
        {
            "info": "alexa"
        },
        {
            "info":"FortiguardReputation"
        },
        {
            "passive": "dig"
        },
        {
            "passive": "pynslookup"
        },
        {
            "passive": "traceroute"
        },
        {
            "passive": "wget"
        },
        {
            "passive": "screenshot"
        },
        {
            "passive": "cert"
        },
        {
            "active":"jarmwrapper"
        }
    ]
}

```

You'll note the conf file is structured into JSON, so carefully note the placement of brackets, quotes and commas when editing.

3. If you don't wish to use logging and rely on the screen output, modify this line:

```bash
    "logger": "true",
```
Change "true" to "false"

4. If you'd to use logging, modify this line:

```bash
    "logroot": "<add your log directory>",
```

Replace <add your log directory> with your desired log location and remember to include a "/" (without the quotes) as the last character.


## Mirage Modules With API Keys

Three pre-built Mirage modules require API keys from the organizations supplying the data.  These are the VirusTotal, IBM X-Force and Shodan modules.  Accounts with each both organization are free and come out of the box with API access which can be obtained here for [VirusTotal](https://www.virustotal.com/gui/join-us), here for [IBM X-Force](https://www.ibm.com/security/xforce) and here for [Shodan](https://account.shodan.io/register).

1. To edit the VirusTotal modules VTIPReport and VTDomainReport, use the following command:  

```bash
nano /opt/mirage/modules/VTIPReport.py
```
OR 

```bash
nano /opt/mirage/modules/VTDomainReport.py
```

2. Where you see the following lines:

```bash
    #Add your VirusTotal API key inside the quotes on the line below <--------------------------
    apikey = ''
```

Add the VirusTotal API key inside the quotes.
  
3. To edit the IBM X-Force module, use the following command:  

```bash
nano /opt/mirage/modules/XForceReputation.py
```
4. Where you see the following lines:

```bash
    #Add your IBM X-Force API Key and Password inside the quotes on the lines below <--------------------------
    
    APIKey = ''
    APIPassword = ''

```
Enter the API key and it's associated password on the lines provided inside the quotes.

5.  To edit the Shodan module, use the following command:

```bash
nano /opt/mirage/modules/Shodan.py
```

6.  Where you see the following line:

```bash
    #Add your Shodan API key inside the quotes on the line below <--------------------------
    apikey = ''
```

Add the Shodan API key inside the quotes.
