# DYNLIB
This is an IDA Pro plugin to aid in reverse engineering PS4 user mode elf's by loading the PS4 specific DYNLIBDATA segment.

### Features
* Resolves obfuscated symbols NID's in order to label imports and exports
* Loads the symbol table 
* Patches relocations

### Building
#### Requirements
* Visual Studio 2017 
* IDA SDK (6.8 under Win32 Configuration, 7.0 under x64 Configuration)

You may need to reconfigure `Additional Library Directories` and `Additional Include Directories` to point to the correct path of your IDA SDK installation.

### Usage
dynlib.xml is a database of NID's and their matching original symbols. It is required in order to resolve NID's and must be kept updated in order to ensure the plugin can resolve more NID's.

You will need to install dynlib.xml and dynlib64.dll into IDA Pro's plugins folder.

Then you may either press `Ctrl + F-10` or navigate to `Edit > Plugins > DYNLIB`. You will then need to choose the same PS4 elf originally loaded for the database.