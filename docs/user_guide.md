## Mirage v0.9 - User Guide

----

## Simple Examples For Getting Started

The Mirage help screen can be shown by typing the following:

```bash
/opt/mirage/mirage.py --help
```

All flags must be preceded by 2 hyphens "--".

Typical parameters for exploring an external host without touching it directly:

```bash
/opt/mirage/mirage.py --domain --target example.com --type info --modules all
```
This will execute the tool against example.com and run all modules that have been identified in the conf file as "info".

## Command-line Usage Information

Mirage has several command-line flags which are described below.

| Flag | Description |
|------------|-------------|
| ThreatCrowdReputation | Required - Tells Mirage what type of target is being investigated |
| --target OR --targetlist | Required - Investigate a single IP or domain or an entire list of them |
| --type | Required - Info, Passive, Active or All - Determine what block of modules to use |
| --modules | Required - Specific or All - What specific modules to use or all of them for a particular type |
| --sleeptime | The number of seconds paused between targets |
| --output | Put the output of the tool in a specific directory |
| --nolinksummary | leave out links in the summary file to keep it clean and simple. |
| --listmodules | Prints a list of available modules and their descriptions. |
| --listaddintypes | Prints a list of available addin types as defined in the mirage.conf file.  Defines a group of modules to run. |
| --updatefeeds | Update the feeds used for the --type info switch. |
| --debug | Prints verbose logging to the screen to troubleshoot issues with a Mirage installation.|
| --help | Prints list of flags |

## Default Modules

The modules that come standard with Mirage are as follows:

| Module | Type | Description |
|------|-------------|---------|
| ThreatCrowdReputation | Info | Retrieves the reputation data for domains and IPs against the ThreatCrowd database |
| XForceReputation | Info | Retrieves the reputation data for domains and IPs against the IBM X-Force Exchange database |
| VTIPReport | Info | Retrieves the reputation data for IPs against the VirusTotal database. |
| VTDomainReport | Info | Retrieves the reputation data for domains against the VirusTotal database |
| FortiguardReputation | Info | Retrieves the categorization data for domains and IPs against Fortiguard's database |
| Shodan | Info | Retrieves the available data for targets against the Shodan dataset |
| whois | Info | Queries the WhoIs information for a target |
| tor_node | Info |  Executes a grep against the current TorDNSEL list of exit nodes |
| abuse_ch_ransomware_ips | Info | Executes a grep against the abuse.ch ransomware IPs feed |
| abuse_ch_ransomware_domains | Info | Executes a grep against the abuse.ch ransomware domains feed |
| abuse_ch_ransomware_urls | Info | Executes a grep against the abuse.ch ransomware URLs feed |
| abuse_ch_feodo | Info | Executes a grep against the abuse.ch Feodo IP blocklist feed |
| abuse_ch_urlhaus_host | Info | Executes a grep against the abuse.ch URLHaus blocklist feed |
| alexa | Info | Executes a grep against the top 1 million Internet domains on Alexa |
| dig | Passive | Executes Dig against the target |
| pynslookup | Passive | Executes NSLookup  against the target |
| traceroute | Passive | Executes a traceroute against the target *Requires root privileges!!!*|
| wget | Passive/Active | Executes a WGet operation against the target |
| screenshot | Passive/Active | Uses the Selenium web driver to take a screenshot of the web site |
| cert | Active | Pulls the target's certificate data using OpenSSL |
| jarmwrapper | Active | Fingerprints the site using Salesforce's Jarm |

### Feeds

Several modules in the Info type set use feeds from 3rd parties to determine whether a host is malicious, previously seen or otherwise interesting.  The feeds that ship with the install are:

| Feed | Description |
|------------|-------------|
| feodo_ipblocklist.txt | Abuse.ch IP list of current Feodo (Dridex and Emotet are derivatives) C2s |
| RW_DOMBL.txt | Abuse.ch ransomware domains |
| RW_IPBL.txt | Abuse.ch ransomware IPs |
| RW_URLBL.txt | Abuse.ch ransomware URLs |
| top-1m.csv | Alexa top 1 million websites |
| ToR_Exits.txt | List of ToR Exit Nodes |
| URLHaus.txt | URLHaus malware domains |

In the event you create a module that incorporates another feed, it can be added to the update script so it gets refreshed with the others.  To do so:

```bash
sudo nano /opt/mirage/updatefeeds.sh
```

Once in look for the update function where the individual feeds are updated and add your own.

```bash
update_feeds() {
  #Pull Feodo IP Blocklist from Abuse.ch and update
  echoinfo "Updating Feodo IP Blocklist from Abuse.ch"
  wget -q "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist" --output-document "/tmp/feodo_ipblocklist.txt"
  chmod a+w "/tmp/feodo_ipblocklist.txt"
  mv "/tmp/feodo_ipblocklist.txt" "$FEEDS_DIR"
```

### The config file

The Mirage config file contains settings for how the tool behaves and what modules to run.  To access, open the following file:

```bash
sudo nano /opt/mirage/mirage.conf
```

The file is structured for JSON and settings are in the format of "setting":"value",.  The quotes are required as is the comma at the end.  The defaults settings are described below: 

| Setting | Description |
|------------|-------------|
| "logger" | true or false - Determines whether built in logging is used.  If false, output will still be directed to the console |
| "logroot" | directory - If the above option is true, this will be the directory where default output is logged.  Remember the trailing "/" at the end of the directory |
| "modulesdir" | directory - Directory where modules are stored.  By default it's /opt/mirage/modules/.   |
| "useragent" | Browser user-agent string for any modules that require web-based contact.  "default" by default |
| "sleeptime" | Time to wait between targets.  7 seconds by default. |
| "addintypes" | "active","passive","info" are the default module types.  |
| "addins" | These are the actual modules |

The config file in its entirety is:

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

### Running

There are multiple ways to explore a target.  

To access a single module, run the following:

```bash
/opt/mirage/mirage.py --domain --target google.com --type info --modules whois
```

To direct output to a specific location:

```bash
/opt/mirage/mirage.py --domain --target google.com --type info --modules all --output /home/yourname/yourdirectory
```

To use a list of targets from a file:

```bash
/opt/mirage/mirage.py --domain --targetlist yourlist.txt --type info --modules all --output /home/yourname/yourdirectory
```

To output a summary to a CSV file:

```bash
/opt/mirage/mirage.py --domain --targetlist yourlist.txt --type info --modules all --output /home/yourname/yourdirectory --csv
```

Output to the console will look like the following:

```bash
$ /opt/mirage/mirage.py --domain --target google.com --type info --modules all 
[*] Arguments: 
domain: True
target: google.com
type: info
modules: all
[*] Type is info
[*] Logger is active
[*] Creating log file
[-] Organize Modules...

[*] Running ThreatCrowd reputation against: google.com
[-] Malware hashes have been found associated with this target...
[-] Subdomains have been found associated with this target...
[*] ThreatCrowd JSON output data had been written to file here: /home/scalp/miragelogs/google.com/TC_JSON_Output.json

[*] Running X-Force reputation against: google.com
[*] X-Force reputation data had been written to file here: /home/scalp/miragelogs/google.com/XForceReputation.json

[*] Running URLScan.io data against: google.com
[*] UrlScan JSON output data had been written to file here: /home/scalp/miragelogs/google.com/URLScanio_JSON_Output.json

[*] Running VT reputation against: google.com
[-] Target has been flagged for malware
[*] VirusTotal reputation data had been written to file here: /home/scalp/miragelogs/google.com/VTReputation.json

[*] Running Fortiguard reputation against: google.com
[*] Target has been categorized by Fortiguard as: Search Engines and Portals
[*] Fortiguard reputation data had been written to file here: /home/scalp/miragelogs/google.com/FortiguardReputation.txt
[*] Fortiguard HTML output data had been written to file here: /home/scalp/miragelogs/google.com/Fortiguard_Output.html

[*] Running WhoIs against: google.com
[*] Country Code: Registrant Country: US

[*] WhoIs data had been written to file here: /home/scalp/miragelogs/google.com/WhoIs.txt

[-] Unable to execute ToR Node IP grep - target must be an IP - skipping.

[-] Unable to execute abuse.ch ransomware IP grep - target must be an IP - skipping.

[*] Running abuse.ch ransomware domain grep against: google.com
[-] Target does not appear in the abuse.ch ransomware domains feed
[x] abuse.ch ransomware domain data not written to file

[*] Running abuse.ch ransomware URL grep against: google.com
[-] Target does not appear in the abuse.ch Ransomware URLs feed
[x] abuse.ch ransomware URL data not written to file

[-] Unable to execute abuse.ch Feodo IP grep - target must be an IP - skipping.

[*] Running abuse.ch URLHaus grep against: google.com
[-] Target has 1022 entries in the abuse.ch URLHaus feed.
[*] abuse.ch URLHaus data had been written to file here: /home/scalp/miragelogs/google.com/URLHaus.csv

[*] Running Alexa grep against: google.com
[-] Target does appear in the Alexa rankings.
[*] Log file written to: /home/scalp/miragelogs/google.com/google.com.html
[*] Program Complete
```

When logging is enabled, it will be deposited into a subdirectory that has the target host's domain or IP for name.  There will be an HTML file that will have a summary as well as hyperlinks to each log file.

### Creating additional modules

In the Mirage directory, there is an example template for a new module to be created.  To access:

```bash
nano /opt/mirage/example_module.py
```

This file contains instructions on how to get your module working.  It will need to be deposited into the modules subdirectory and an entry will need to be added to the Mirage config file under the addins setting.
