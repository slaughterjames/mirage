'''
Mirage v0.4 - Copyright 2017 James Slaughter,
This file is part of Mirage v0.4.

Mirage v0.4 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Mirage v0.4 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Mirage v0.4.  If not, see <http://www.gnu.org/licenses/>.
'''

'''
logger.py - This file is responsible for providing a mechanism to write 
log files to the hard drive and read in the static.conf file


logger
Class: This class is responsible for providing a mechanism to write
       log files to the hard drive and read in the static.conf file
       - Uncomment commented lines in the event troubleshooting is required
        
'''

#python imports
import sys
import os
import datetime

#programmer generated imports
from fileio import fileio

class logger:
    
    '''
    Constructor
    '''
    def __init__(self):
        
        self.startdatetime = ''  

    '''
    ReportCreate()
    Function: - Creates a new log file based on the target
              - Adds a header to the log 
    '''     
    def ReportCreate(self, logdir, targetlist):  
        logroot = logdir + 'logroot.html'
        FLog = fileio()
        
        self.startdatetime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
        filename = logroot

        data = '<html>\n'
        data += '\n--------------------------------------------------------------------------------'
        data += '---------------------------------------<br/>'
        data += '<head>\n<title>'+ '</title>\n'
        data += '\n<strong>Starting Analysis On Targetlist: ' + str(targetlist) + '</strong>' + '\n' 
        data += '\n<br/><strong>Date/Time: </strong>' + self.startdatetime + '<br/>\n'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------<br/>\n</head>\n<body>\n'
        FLog.WriteNewLogFile(filename, data)
   
        return 0 

    '''

    ReportFooter()
    Function: - Adds a footer to close out the log file created in the function above
              - 
              -  
    '''     
    def ReportFooter(self, logdir):  
        FLog = fileio()        
        filename = logdir + 'logroot.html'        
        data = '<strong>END OF FILE</strong><br/>'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------\n<br/>'
        data += 'Processed by Mirage v0.4\n<br/>'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------\n<br/>'
        data += '\n</body>\n</html>\n'
        FLog.WriteLogFile(filename, data)
        print '\n'
        print '[*] Report file written to: ' + filename
           
        return 0

    '''    
    WriteReport()
    Function: - Writes to the current log file            
              - Returns to the caller
    '''    
    def WriteReport(self, logdir, newlogline):  
        FLog = fileio()
        filename = logdir + 'logroot.html'
        data = str(newlogline) #+ '\n<br/>'
        FLog.WriteLogFile(filename, data)
           
        return 0 

    '''
    LogCreate()
    Function: - Creates a new log file based on the target
              - Adds a header to the log                
    '''     
    def LogCreate(self, logdir, target):  
        logroot = logdir + 'logroot.html'
        FLog = fileio()
        
        self.startdatetime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
        filename = logdir + target + '.html'
        data = '<html>\n'
        data += '\n--------------------------------------------------------------------------------'
        data += '---------------------------------------<br/>'
        data += '<head>\n<title>' + filename + '</title>\n'
        data += '\n<strong>Starting Analysis On Target: ' + target + '</strong>' + '\n' 
        data += '\n<br/><strong>Date/Time: </strong>' + self.startdatetime + '<br/>\n'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------<br/>\n</head>\n<body>\n'
        FLog.WriteNewLogFile(filename, data)
           
        return 0   
    
    '''
    LogFooter()
    Function: - Adds a footer to close out the log file created in the function above
    '''     
    def LogFooter(self, logdir, target):  
        FLog = fileio()        
        filename = logdir + target + '.html'        
        data = '--------------------------------------------------------------------------------'
        data += '---------------------------------------\n<br/>'
        data += 'Processed by Mirage v0.4\n<br/>'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------\n<br/>'
        data += '\n</body>\n</html>\n'
        FLog.WriteLogFile(filename, data)
        print '[*] Log file written to: ' + filename
           
        return 0       
        
    '''    
    WriteLog()
    Function: - Writes to the current log file            
              - Returns to the caller
    '''    
    def WriteLog(self, logdir, target, newlogline):  
        FLog = fileio()
        filename = logdir + target + '.html'
        data = newlogline + '\n<br/>'
        FLog.WriteLogFile(filename, data)
           
        return 0 

'''
TableCell
Class: This class is responsible for providing a mechanism to create a cell in an HTML table (TD or TH)
       
'''
class TableCell (object):

    '''
    Attributes:
    - text: text in the cell (may contain HTML tags). May be any object which
            can be converted to a string using str().
    - header: bool, false for a normal data cell (TD), true for a header cell (TH)
    - bgcolor: str, background color
    - width: str, width
    - align: str, horizontal alignement (left, center, right, justify or char)
    - char: str, alignment character, decimal point if not specified
    - charoff: str, see HTML specs
    - valign: str, vertical alignment (top|middle|bottom|baseline)
    - style: str, CSS style
    - attribs: dict, additional attributes for the TD/TH tag

    Reference: http://www.w3.org/TR/html4/struct/tables.html#h-11.2.6
    '''

    def __init__(self, text="", bgcolor=None, header=False, width=None,
                align=None, char=None, charoff=None, valign=None, style=None,
                attribs=None):
        '''
        Constructor
        '''
        self.text    = text
        self.bgcolor = bgcolor
        self.header  = header
        self.width   = width
        self.align   = align
        self.char    = char
        self.charoff = charoff
        self.valign  = valign
        self.style   = style
        self.attribs = attribs
        if attribs==None:
            self.attribs = {}

    def __str__(self):

        attribs_str = ""
        if self.bgcolor: self.attribs['bgcolor'] = self.bgcolor
        if self.width:   self.attribs['width']   = self.width
        if self.align:   self.attribs['align']   = self.align
        if self.char:    self.attribs['char']    = self.char
        if self.charoff: self.attribs['charoff'] = self.charoff
        if self.valign:  self.attribs['valign']  = self.valign
        if self.style:   self.attribs['style']   = self.style
        for attr in self.attribs:
            attribs_str += ' %s="%s"' % (attr, self.attribs[attr])
        if self.text:
            text = str(self.text)
        else:
            # An empty cell should at least contain a non-breaking space
            text = '&nbsp;'
        if self.header:
            return '  <TH%s>%s</TH>\n' % (attribs_str, text)
        else:
            return '  <TD%s>%s</TD>\n' % (attribs_str, text)


'''
TableRow
Class: This class is responsible for providing a mechanism to create a row in a HTML table. (TR tag)
       
'''
class TableRow (object):
    '''
    Attributes:
    - cells: list, tuple or any iterable, containing one string or TableCell
             object for each cell
    - header: bool, true for a header row (TH), false for a normal data row (TD)
    - bgcolor: str, background color
    - col_align, col_valign, col_char, col_charoff, col_styles: see Table class
    - attribs: dict, additional attributes for the TR tag

    Reference: http://www.w3.org/TR/html4/struct/tables.html#h-11.2.5
    '''

    def __init__(self, cells=None, bgcolor=None, header=False, attribs=None,
                col_align=None, col_valign=None, col_char=None,
                col_charoff=None, col_styles=None):
        '''
        Constructor
        '''
        self.bgcolor     = bgcolor
        self.cells       = cells
        self.header      = header
        self.col_align   = col_align
        self.col_valign  = col_valign
        self.col_char    = col_char
        self.col_charoff = col_charoff
        self.col_styles  = col_styles
        self.attribs     = attribs
        if attribs==None:
            self.attribs = {}

    def __str__(self):

        attribs_str = ""
        if self.bgcolor: self.attribs['bgcolor'] = self.bgcolor
        for attr in self.attribs:
            attribs_str += ' %s="%s"' % (attr, self.attribs[attr])
        result = ' <TR%s>\n' % attribs_str
        for cell in self.cells:
            col = self.cells.index(cell)    # cell column index
            if not isinstance(cell, TableCell):
                cell = TableCell(cell, header=self.header)
            # apply column alignment if specified:
            if self.col_align and cell.align==None:
                cell.align = self.col_align[col]
            if self.col_char and cell.char==None:
                cell.char = self.col_char[col]
            if self.col_charoff and cell.charoff==None:
                cell.charoff = self.col_charoff[col]
            if self.col_valign and cell.valign==None:
                cell.valign = self.col_valign[col]
            # apply column style if specified:
            if self.col_styles and cell.style==None:
                cell.style = self.col_styles[col]
            result += str(cell)
        result += ' </TR>\n'
        return result


'''
Table
Class: This class is responsible for providing a mechanism to create an HTML table.
       
'''
class Table (object):

    '''
    Attributes:
    - rows: list, tuple or any iterable, containing one iterable or TableRow
            object for each row
    - header_row: list, tuple or any iterable, containing the header row (optional)
    - border: str or int, border width
    - style: str, table style in CSS syntax (thin black borders by default)
    - width: str, width of the table on the page
    - attribs: dict, additional attributes for the TABLE tag
    - col_width: list or tuple defining width for each column
    - col_align: list or tuple defining horizontal alignment for each column
    - col_char: list or tuple defining alignment character for each column
    - col_charoff: list or tuple defining charoff attribute for each column
    - col_valign: list or tuple defining vertical alignment for each column
    - col_styles: list or tuple of HTML styles for each column

    Reference: http://www.w3.org/TR/html4/struct/tables.html#h-11.2.1
    '''

    def __init__(self, rows=None, border='1', style=None, width=None,
                cellspacing=None, cellpadding=4, attribs=None, header_row=None,
                col_width=None, col_align=None, col_valign=None,
                col_char=None, col_charoff=None, col_styles=None):
        '''
        Constructor
        '''
        self.border = border
        self.style = style
        # style for thin borders by default
        if style == None: self.style = 'TABLE_STYLE_THINBORDER'
        self.width       = width
        self.cellspacing = cellspacing
        self.cellpadding = cellpadding
        self.header_row  = header_row
        self.rows        = rows
        if not rows: self.rows = []
        self.attribs     = attribs
        if not attribs: self.attribs = {}
        self.col_width   = col_width
        self.col_align   = col_align
        self.col_char    = col_char
        self.col_charoff = col_charoff
        self.col_valign  = col_valign
        self.col_styles  = col_styles

    def __str__(self):

        attribs_str = ""
        if self.border: self.attribs['border'] = self.border
        if self.style:  self.attribs['style'] = self.style
        if self.width:  self.attribs['width'] = self.width
        if self.cellspacing:  self.attribs['cellspacing'] = self.cellspacing
        if self.cellpadding:  self.attribs['cellpadding'] = self.cellpadding
        for attr in self.attribs:
            attribs_str += ' %s="%s"' % (attr, self.attribs[attr])
        result = '<TABLE%s>\n' % attribs_str
        # insert column tags and attributes if specified:
        if self.col_width:
            for width in self.col_width:
                result += '  <COL width="%s">\n' % width

        # First insert a header row if specified:
        if self.header_row:
            if not isinstance(self.header_row, TableRow):
                result += str(TableRow(self.header_row, header=True))
            else:
                result += str(self.header_row)
        # Then all data rows:
        for row in self.rows:
            if not isinstance(row, TableRow):
                row = TableRow(row)
            # apply column alignments  and styles to each row if specified:
            # (Mozilla bug workaround)
            if self.col_align and not row.col_align:
                row.col_align = self.col_align
            if self.col_char and not row.col_char:
                row.col_char = self.col_char
            if self.col_charoff and not row.col_charoff:
                row.col_charoff = self.col_charoff
            if self.col_valign and not row.col_valign:
                row.col_valign = self.col_valign
            if self.col_styles and not row.col_styles:
                row.col_styles = self.col_styles
            result += str(row)
        result += '</TABLE>'
        return result



'''
Table
Class: This class is responsible for providing a mechanism to create an list object.
       
'''
class List (object):

    '''
    Attributes:
    - lines: list, tuple or any iterable, containing one string for each line
    - ordered: bool, choice between an ordered (OL) or unordered list (UL)
    - attribs: dict, additional attributes for the OL/UL tag

    Reference: http://www.w3.org/TR/html4/struct/lists.html
    '''

    def __init__(self, lines=None, ordered=False, start=None, attribs=None):
        """List constructor"""
        if lines:
            self.lines = lines
        else:
            self.lines = []
        self.ordered = ordered
        self.start = start
        if attribs:
            self.attribs = attribs
        else:
            self.attribs = {}

    def __str__(self):

        attribs_str = ""
        if self.start:  self.attribs['start'] = self.start
        for attr in self.attribs:
            attribs_str += ' %s="%s"' % (attr, self.attribs[attr])
        if self.ordered: tag = 'OL'
        else:            tag = 'UL'
        result = '<%s%s>\n' % (tag, attribs_str)
        for line in self.lines:
            result += ' <LI>%s\n' % str(line)
        result += '</%s>\n' % tag
        return result

