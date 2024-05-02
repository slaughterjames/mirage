#!/bin/bash -
#===============================================================================
#Mirage v1.0 - Copyright 2024 James Slaughter,
#This file is part of Mirage v1.0.

#Mirage v1.0 is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#Mirage v1.0 is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with Mirage v1.0.  If not, see <http://www.gnu.org/licenses/>.
#===============================================================================
#------------------------------------------------------------------------------
#
# Install Mirage Intel Feed Updates.
#
#------------------------------------------------------------------------------

__ScriptVersion="updatefeeds-v0.9-3"
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
  wget -q "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt" --output-document "$FEEDS_DIR/ipblocklist_aggressive.txt"
  chmod a+w "$FEEDS_DIR/ipblocklist_aggressive.txt"

  #Pull ToR Exit Node List from Torproject.org and update
  echoinfo "Updating ToR Exit Node List from Torproject.org"
  wget -q "https://check.torproject.org/exit-addresses" --output-document "$FEEDS_DIR/ToR_Exits.txt"
  chmod a+w "$FEEDS_DIR/ToR_Exits.txt"

  #Pull Majestic Million Domains and update
  echoinfo "Updating Majestic Million Feed"
  wget -q "https://downloads.majestic.com/majestic_million.csv" --output-document "/tmp/majestic_million.csv"
  cut -d',' -f3 "/tmp/majestic_million.csv" > "/tmp/majestic_update.csv"
  chmod a+w "/tmp/majestic_update.csv"
  mv "/tmp/majestic_update.csv" "$FEEDS_DIR"
  rm "/tmp/majestic_million.csv"
  chmod a+w "$FEEDS_DIR/majestic_update.csv"  

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
