mirage v0.3 - Copyright 2014 James Slaughter,
This file is part of mirage v0.3.

mirage v0.3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

mirage v0.3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with mirage v0.3.  If not, see <http://www.gnu.org/licenses/>.

Usage: [required] --ip [OR] --domain [optional] --supresswget --supressnmap --supresscert --debug --help
    Required Arguments:
    --ip - the IP address of the resource you are investigating
    OR
    --domain (without http://) - the domain of the resournce you are investigating
    Optional Arguments:
    --url - the full address of the resource you are investigating.
    --supresswget - will not attempt a WGET against the target.
    --supressnmap - will not perform a port scan against the target.  Will automatically
    suspend --supresswget and --supresscert as well.
    --supresscert - will not try to pull certificate data from any SSL enabled HTTP port.
    --debug - prints verbose logging to the screen to troubleshoot issues with a recon installation.
    --help - You're looking at it!

mirage.conf settings:
#mirage Log Directory
logdir <Your log directory>

#User Agent
useragent default

#VirusTotal API key- enter yours if you have one
apikey default

CHANGELOG VERSION V0.3:
- Fixed some issues with WGet.  The preservation of the headers was causing issues to the file integrity.
- Added the ability to run the target domain or ip through VirusTotal's reputation engine if you've signed
  up and have an API key.  If you don't want to use this functionality, leave the mirage.conf setting as 
  default.
- In adding the above functionality, you will need to download and install the simplejson package from:
  https://github.com/simplejson/simplejson

CHANGELOG VERSION v0.2:
- Merged code from PYRecon 0.4 to add a line in the mirage config file to allow WGet to use a browser user-agent string.
- Added the --url input arg so wget will mirror and download everything residing at or near a particular web resource.
