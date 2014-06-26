autobreak-api
============

Autobreak-api parses a Windows portable executable (PE) to automatically set breakpoints on all imported functions.  As such, autobreak-api is useful for quick triage of PE files.  Furthermore, the script works well when attempting to show someone who does not have any experience with debugging the ropes, so to say.

Autobreak-api uses the Immunity Log to denote successful breakpoint additions along with any errors.  If the script runs into an error, this is most likely because Immunity cannot set a breakpoint on an identified memory address.  No biggie :).

-----

### Prerequisites

* Requires pefile
* Requires immlib and imm (included with Immunity Debugger)

* This code has been tested under Immunity Debugger 1.8x using a Python 2.7.6 install

-----

### Installation

* 1) Install pefile (if already installed, add --upgrade to attempt an upgrade)

```
sudo pip install pefile
```

* 2) Copy ```autobreak-api.py``` to the PyCommands in your Immunity install folder

-----

### Usage

The script does not require any arguments.  Simply copy the script to the PyCommand folder in your Immunity install directory and then run from Immunity's Command Bar.

```
!autobreak-api
```

-----

### Sources

The idea for setting breakpoints on imported functions came from Joe Giron's ```joebp.py``` script:

http://www.gironsec.com/code/joebp.py

I simply setup my script to parse the PE to find imported functions, whereas Joe's script has specific functions denoted upon which one can set a breakpoint.

