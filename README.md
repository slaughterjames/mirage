## Mirage v0.9

Mirage is a tool designed to help security professionals perform OSINT information gathering using open, passive and active techniques.  With modularity built-in to the tool, it is easy to create new modules quickly to solve new and unforseen problems in obtaining information.

This tool lends itself to both offensive(bug bounty reconnaisance) and defensive techniques (intelligence on malicious IPs and domains)

**Pre-built Modules:**

* **[*] ThreatCrowdReputation:** Type: Info - Description: Retrieves the reputation data for domains and IPs against the ThreatCrowd database.
* **[*] XForceReputation:** Type: Info - Description: Retrieves the reputation data for domains and IPs against the IBM X-Force Exchange database.
* **[*] VTIPReport:** Type: Info - Description: Retrieves the reputation data for IPs against the VirusTotal database.
* **[*] VTDomainReport:** Type: Info - Description: Retrieves the reputation data for domains against the VirusTotal database
* **[*] FortiguardReputation:** Type: Info - Description: Retrieves the categorization data for domains and IPs against Fortiguard's database.
* **[*] Shodan:** Type: Info - Description: Retrieves the available data for targets against the Shodan dataset.
* **[*] whois:** Type: Info - Description: Queries the WhoIs information for a target
* **[*] tor_node:** Type: Info - Description: Executes a grep against the current TorDNSEL list of exit nodes.
* **[*] abuse_ch_ransomware_ips:** Type: Info - Description: Executes a grep against the abuse.ch ransomware IPs feed.
* **[*] abuse_ch_ransomware_domains:** Type: Info - Description: Executes a grep against the abuse.ch ransomware domains feed.
* **[*] abuse_ch_ransomware_urls:** Type: Info - Descripition: Executes a grep against the abuse.ch ransomware URLs feed.
* **[*] abuse_ch_feodo:** Type: Info - Description: Executes a grep against the abuse.ch Feodo IP blocklist feed.
* **[*] abuse_ch_urlhaus_host:** Type: Info - Description: Executes a grep against the abuse.ch URLHaus blocklist feed.
* **[*] alexa:** Type: Info - Description: Executes a grep against the top 1 million Internet domains on Alexa.
* **[*] dig:** Type: Passive - Description: Executes Dig against the target.
* **[*] pynslookup:** Type: Passive - Description: Executes an NSLookup against the target.
* **[*] traceroute:** Type: Passive - Description: Executes a traceroute against the target. *Requires root privileges!!!*
* **[*] wget:** Type: Passive/Active - Description: Executes a WGet operation against the target
* **[*] screenshot:** Type: Passive/Active - Description: Uses the Selenium web driver to take a screenshot of the web site.
* **[*] cert:** Type: Active - Description: Pulls the target's certificate data using OpenSSL
* **[*] jarmwrapper:** Type: Active - Description: Fingerprints the site using Salesforce's Jarm 
----

## Documentation

Use the [Installation Guide](https://github.com/slaughterjames/mirage/blob/master/docs/install.md) to get started.

Go to the [User's Guide](https://github.com/slaughterjames/mirage/blob/master/docs/user_guide.md) for additional information.
