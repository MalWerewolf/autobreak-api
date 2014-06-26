DESC = """ =============================================================
autobreak-api
by 8bits0fbr@in -- Twitter: 8bits0fbrain

        Parses the open PE file in Immunity Debugger and sets breakpoints
        on the WinAPI functions found in the PE's import table.

        Note: Since the PE's imports must be readable, this tool
        requires an unpacked/unencryptd PE!

        Requirements:
        pefile, immlib, immutils
========================================================================
"""

NAME = 'autobreak-api'
__VERSION__ = '1.0'

import getopt
import re

import pefile

import immlib
import immutils
from immutils import *

# Instantiate the Debugger() class as imm
imm = immlib.Debugger()

def setup():
        """Function sets PE-related variables and instantiates appropriate classes.

        Created Variables:
                pe_name   (string) = name of the loaded PE
                pe_module (object) = loaded module (PE) object reference
                pe_path   (string) = path to the loaded PE
                pe        (object) = object for the loaded PE (pefile)
        """
        imm.log(" ")
        imm.log("%s v%s by 8bits0fbr@in" % (NAME, __VERSION__), highlight=1)

        pe_name = imm.getDebuggedName()
        imm.log("[*autobreak-api*] Loaded PE: %s" % pe_name, highlight=1)
        
        pe_module = imm.getModule(pe_name)
        
        pe_path = pe_module.getPath()
        imm.log("[*autobreak-api*] PE Path:   %s" % pe_path, highlight=1)

        # Instantiate the PE object and pass it to parse_pe() for import parsing
        pe = pefile.PE(pe_path)
        parse_pe(pe)

def parse_pe(pe):
        """Function loops through the imports in the loaded PE to
        process imports.  Each import

        Keyword Argument:
                pe (object) = loaded PE object (pefile)

        Created Variables:
                entry    (object) = entry from the loaded PE's import table
                imp      (object) = import itself
                dll_name (string) = entry .dll name with ".dll" stripped
                current_breakpoint (string) = full import name
        """
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                        # Remove the substring ".dll" from the entry.dll name
                        dll_name = re.sub(r'\.dll', '', entry.dll,
                                          flags=re.IGNORECASE)
                        if dll_name and imp.name:
                                # Set full breakpoint name, sans .dll substring
                                current_breakpoint = dll_name + '.' + imp.name
                                # Ensures intended import address exists
                                # and sets breakpoint if available
                                if imm.getAddress(current_breakpoint) > 0:
                                        imm.setBreakpoint(imm.getAddress
                                                          (current_breakpoint))
                                        imm.log("+ Breakpoint Set: %s"
                                        % current_breakpoint)
                                # Logs error if function address not available
                                else:
                                        imm.log('! Address Error:  '
                                                + current_breakpoint)
                                
def main(args):
        """Function checks for provided arguments.  If any args are provided,
        displays an error.  Otherwise, calls setup() to begin exectuion.
        """
        if args:
                exit_code = "[*autobreak-api*] No args -- Use '!autobreak-api'"
        else:
                setup()
                exit_code = "[*autobreak-api*] DONE! Check Immunity's Log!"
        return exit_code
