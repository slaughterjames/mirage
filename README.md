mirage v0.1 - Copyright 2013 James Slaughter,
This file is part of mirage v0.1.

mirage v0.1 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

mirage v0.1 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with mirage v0.1.  If not, see <http://www.gnu.org/licenses/>.

Usage: [required] --target [optional] --supresswget --supressnmap --supresscert --debug --help
    Required Arguments:
    --target[Must be IP to work properly] - the host you are investigating.
    Optional Arguments:
    --supresswget - will not attempt a WGET against the target.
    --supressnmap - will not perform a port scan against the target.  Will automatically
       suspend --supresswget and --supresscert as well.
    --supresscert - will not try to pull certificate data from any SSL enabled HTTP port.
    --debug - prints verbose logging to the screen to troubleshoot issues with a mirage installation.
    --help - You're looking at it!
