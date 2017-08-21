#!/bin/bash -
#===============================================================================
#Mirage v0.4 - Copyright 2017 James Slaughter,
#This file is part of Mirage v0.4.

#Mirage v0.4 is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#Mirage v0.4 is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with Mirage v0.4.  If not, see <http://www.gnu.org/licenses/>.
#===============================================================================
#------------------------------------------------------------------------------
#
# Install Mirage on top of an Ubuntu-based Linux distribution.
#
#------------------------------------------------------------------------------

__ScriptVersion="Mirage-v0.4-1"
LOGFILE="/var/log/mirage-install.log"
DIR="/opt/mirage/"
MODULES_DIR="/opt/mirage/modules/"
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

__apt_get_install_noinput() {
    sudo apt-get install -y -o DPkg::Options::=--force-confold $@; return $?
}

__apt_get_upgrade_noinput() {
    sudo apt-get upgrade -y -o DPkg::Options::=--force-confold $@; return $?
}

__pip_install_noinput() {
    pip install --upgrade $@; return $?
}


usage() {
    echo "usage"
    exit 1
}


install_ubuntu_deps() {

  echoinfo "Updating the base APT repository package list... "
  apt-get update >> $LOGFILE 2>&1

  echoinfo "Upgrading all APT packages to latest versions..."
  __apt_get_upgrade_noinput >> $LOGFILE 2>&1

  ldconfig
  return 0
}

install_ubuntu_packages() {
    #Ubuntu packages that need to be installed
    packages="python
    python-dev
    automake
    python-pip
    python-setuptools
    python-magic
    whois
    traceroute
    dnsutils
    openssl
    nmap"

    if [ "$@" = "dev" ]; then
        packages="$packages"
    elif [ "$@" = "stable" ]; then
        packages="$packages"
    fi

    for PACKAGE in $packages; do
        echoinfo "Installing APT Package: $PACKAGE"
        __apt_get_install_noinput $PACKAGE >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echoerror "Install Failure: $PACKAGE (Error Code: $ERROR)"
        fi
    done    
    
    return 0
}


install_pip_packages() {
  #Python Libraries that need to be installed
  pip_packages="termcolor
  simplejson
  requests
  "

  if [ "$@" = "dev" ]; then
    pip_packages="$pip_packages"
  elif [ "$@" = "stable" ]; then
    pip_packages="$pip_packages"
  fi

  for PACKAGE in $pip_packages; do
    CURRENT_ERROR=0
    echoinfo "Installing Python Package: $PACKAGE"
    __pip_install_noinput $PACKAGE >> $LOGFILE 2>&1 || (let ERROR=ERROR+1 && let CURRENT_ERROR=1)
    if [ $CURRENT_ERROR -eq 1 ]; then
      echoerror "Python Package Install Failure: $PACKAGE"
    fi
  done

  if [ $ERROR -ne 0 ]; then
    return 1
  fi

  return 0
}

install_mirage_package() {
  #Pull Mirage from GitHub, unzip and install it
  echoinfo "Installing Mirage"
  wget -q "https://github.com/slaughterjames/mirage/archive/master.zip" --output-document "/tmp/master.zip"
  unzip -q "/tmp/master.zip" -d "/tmp/"
  chmod a+w "/tmp/mirage-master/" 
  mv "/tmp/mirage-master"/* "$DIR" 
  rm -R "/tmp/mirage-master/"

  if [ $ERROR -ne 0 ]; then
    return 1
  fi

  return 0
}

install_secondary_packages() {
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

  #Pull Alexa Top 1M Domains and update
  echoinfo "Updating Alexa Top 1M Feed"
  wget -q "http://s3.amazonaws.com/alexa-static/top-1m.csv.zip" --output-document "/tmp/top-1m.csv.zip"
  unzip -q "/tmp/top-1m.csv.zip" -d "/tmp/" 
  chmod a+w "/tmp/top-1m.csv"
  mv "/tmp/top-1m.csv" "$FEEDS_DIR"
  rm "/tmp/top-1m.csv.zip"

  return 0
}

configure_mirage() {
  #Creates the necessary directories for Mirage in /opt/mirage
  echoinfo "Creating directories"

  mkdir -p $DIR >> $LOGFILE 2>&1
  chmod a+w $DIR >> $LOGFILE 2>&1

  mkdir -p $MODULES_DIR >> $LOGFILE 2>&1
  chmod a+w $MODULES_DIR >> $LOGFILE 2>&1

  mkdir -p $FEEDS_DIR >> $LOGFILE 2>&1
  chmod a+w $FEEDS_DIR >> $LOGFILE 2>&1

  return 0
}

complete_message() {
    #Message that displays on completion of the process
    echoinfo "---------------------------------------------------------------"
    echoinfo "Mirage Installation Complete!"
    echoinfo "Reboot for the settings to take full effect (\"sudo reboot\")."
    echoinfo "---------------------------------------------------------------"

    return 0
}

#Grab the details about the system
OS=$(lsb_release -si)
ARCH=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(lsb_release -sr)

#Print out details about the system
echo "Installing Mirage on: $OS"
echo "Architecture is: $ARCH bit"
echo "Version is: $VER"
echo ""

#Bail if installation isn't
if [ `whoami` != "root" ]; then
    echoerror "The Mirage installation script must run as root."
    echoerror "Usage: sudo ./get-mirage.sh"
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
        echo "sudo ./get-mirage.sh [options]"
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

if [ "$#" -eq 0 ]; then
    ITYPE="stable"
else
    __check_unparsed_options "$*"
    ITYPE=$1
    shift
fi

echo "---------------------------------------------------------------" >> $LOGFILE
echo "Running Mirage installer version $__ScriptVersion on `date`" >> $LOGFILE
echo "---------------------------------------------------------------" >> $LOGFILE

echoinfo "Installing Mirage. Details logged to $LOGFILE."

#Function calls
install_ubuntu_deps $ITYPE
install_ubuntu_packages $ITYPE
install_pip_packages $ITYPE
configure_mirage
install_mirage_package $ITYPE
install_secondary_packages $ITYPE
complete_message
