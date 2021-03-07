#!/bin/bash -
#===============================================================================
#Mirage v0.9 - Copyright 2021 James Slaughter,
#This file is part of Mirage v0.9.

#Mirage v0.9 is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#Mirage v0.9 is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with Mirage v0.9.  If not, see <http://www.gnu.org/licenses/>.
#===============================================================================
#------------------------------------------------------------------------------
#
# Install Mirage Intel Feed Updates.
#
#------------------------------------------------------------------------------

__ScriptVersion="updatefeeds-v0.9-1"
LOGFILE="/var/log/mirage_updatefeeds.log"
DIR="/opt/mirage/"
FEEDS_DIR="/opt/mirage/feeds/"

echoerror() {
    printf "${RC} * ERROR${EC}: $@\n" 1>&2;
}

echoinfo() {
    printf "${GC} * INFO${EC}: %s\n" "$@";
}

echowarn() {
    printf "${YC} * WARN${EC}: %s\n" "$@";
}

usage() {
    echo "usage"
    exit 1
}

update_feeds() {
  #Pull Feodo IP Blocklist from Abuse.ch and update
  echoinfo "Updating Feodo IP Blocklist from Abuse.ch"
  wget -q "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist" --output-document "/tmp/feodo_ipblocklist.txt"
  chmod a+w "/tmp/feodo_ipblocklist.txt"
  mv "/tmp/feodo_ipblocklist.txt" "$FEEDS_DIR"

  #Pull Ransomware Domain Blacklist from Abuse.ch and update
  echoinfo "Updating Domain Blocklist from Abuse.ch"
  wget -q "http://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt" --output-document "/tmp/RW_DOMBL.txt"
  chmod a+w "/tmp/RW_DOMBL.txt"
  mv "/tmp/RW_DOMBL.txt" "$FEEDS_DIR"

  #Pull Ransomware IP Blacklist from Abuse.ch and update
  echoinfo "Updating IP Blocklist from Abuse.ch"
  wget -q "http://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt" --output-document "/tmp/RW_IPBL.txt"
  chmod a+w "/tmp/RW_IPBL.txt"
  mv "/tmp/RW_IPBL.txt" "$FEEDS_DIR"

  #Pull Ransomware URL Blacklist from Abuse.ch and update
  echoinfo "Updating URL Blocklist from Abuse.ch"
  wget -q "http://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt" --output-document "/tmp/RW_URLBL.txt"
  chmod a+w "/tmp/RW_URLBL.txt"
  mv "/tmp/RW_URLBL.txt" "$FEEDS_DIR"

  #Pull ToR Exit Node List from Torproject.org and update
  echoinfo "Updating ToR Exit Node List from Torproject.org"
  wget -q "https://check.torproject.org/exit-addresses" --output-document "/tmp/ToR_Exits.txt"
  chmod a+w "/tmp/ToR_Exits.txt"
  mv "/tmp/ToR_Exits.txt" "$FEEDS_DIR"

  #Pull Alexa Top 1M Domains and update
  echoinfo "Updating Alexa Top 1M Feed"
  wget -q "http://s3.amazonaws.com/alexa-static/top-1m.csv.zip" --output-document "/tmp/top-1m.csv.zip"
  unzip -q "/tmp/top-1m.csv.zip" -d "/tmp/" 
  chmod a+w "/tmp/top-1m.csv"
  mv "/tmp/top-1m.csv" "$FEEDS_DIR"
  rm "/tmp/top-1m.csv.zip"

  return 0
}

complete_message() {
    #Message that displays on completion of the process
    echoinfo "---------------------------------------------------------------"
    echoinfo "Mirage Feeds Update Complete!"
    echoinfo "---------------------------------------------------------------"

    return 0
}

#Grab the details about the system
OS=$(lsb_release -si)
ARCH=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(lsb_release -sr)

#Print out details about the system
echo "Updating Mirage feeds on: $OS"
echo "Architecture is: $ARCH bit"
echo "Version is: $VER"
echo ""

#Bail if installation isn't root
if [ `whoami` != "root" ]; then
    echoerror "The Static installation script must run as root."
    echoerror "Usage: sudo ./updatefeeds.sh"
    exit 3
fi

if [ "$SUDO_USER" = "" ]; then
    echoerror "The SUDO_USER variable doesn't seem to be set"
    exit 4
fi

while getopts ":hvnicu" opt
do
case "${opt}" in
    h ) echo "Usage:"
        echo ""
        echo "sudo ./updatefeeds.sh"
        echo ""
        exit 0
        ;;
    v ) echo "$0 -- Version $__ScriptVersion"; exit 0 ;;
    \?) echo ""
        echoerror "Option does not exist: $OPTARG"
        usage
        exit 1
        ;;
esac
done

shift $(($OPTIND-1))

echo "---------------------------------------------------------------" >> $LOGFILE
echo "Running Mirage Feeds Updator Version $__ScriptVersion on `date`" >> $LOGFILE
echo "---------------------------------------------------------------" >> $LOGFILE

echoinfo "Updating Mirage Feeds. Details logged to $LOGFILE."

#Function calls
update_feeds
complete_message
