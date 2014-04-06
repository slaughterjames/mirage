mirage v0.2 - Copyright 2014 James Slaughter,
This file is part of mirage v0.2.

mirage v0.2 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

mirage v0.2 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with mirage v0.2.  If not, see <http://www.gnu.org/licenses/>.

Usage: [required] --target [optional] --supresswget --supressnmap --supresscert --debug --help
    Required Arguments:
    --target[can be domain(without http://) or IP] - the host you are investigating.
    Optional Arguments:
    --url - the full address of the resource you are investigating.
    --supresswget - will not attempt a WGET against the target.
    --supressnmap - will not perform a port scan against the target.  Will automatically
    suspend --supresswget and --supresscert as well.
    --supresscert - will not try to pull certificate data from any SSL enabled HTTP port.
    --debug - prints verbose logging to the screen to troubleshoot issues with a recon installation.
    --help - You're looking at it!

CHANGELOG VERSION v0.2:
- Merged code from PYRecon 0.4 to add a line in the mirage config file to allow WGet to use a browser user-agent string
- Added the --url input arg so wget will mirror and download everything residing at or near a particular web resource.
