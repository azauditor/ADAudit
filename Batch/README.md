### Batch Version

**This version of the scripts is completely unsupported. This is stored here only for historical purposes and for the use in the rare environment that has no PowerShell access.**

1. Download the files from the 'Batch' folder in this repository (.zip) or clone the repository
1. Download the [GPMC Sample Scripts](https://gallery.technet.microsoft.com/group-policy-management-17a5f840) developed by Microsoft
1. Download [7-Zip Extra](http://www.7-zip.org/download.html) for the standalone console version
1. Compile the necessary files in a folder structure, as shown below (root folder name is inconsequential):
    * AD
        * .\supplemental\DumpSOMInfo.wsf
        * .\supplemental\GetReportsForAllGPOs.wsf
        * .\supplemental\7za.exe
        * .\Get-ADAuditData.cmd
1. Execute Get-ADAuditData.cmd either directly on server or from management workstation with RSAT installed.
    * **If running directly on server, you should run from an Adminstrative Command Prompt (Avoids UAC issues).**
1. Take resulting .7z archive to audit computer for analysis
    * Sample filename: DC=contoso,DC=com.7z



## Cleaning resultant data post-extraction (Batch Version Only)

After the data has been extracted, and you have retrieved the .7z archive, the data needs to "cleaned". Due to internal data formats in Active Directory, and the way in which csvde.exe extracts the data, some critical data fields are not in human-readable formats. As a companion to the scripts to extract data, a Python Script was developed to clean up the data, changing data columns into human-readable formats. In addition, the script also changes the data from comma-delimited to pipe-delimited, for easier import into SQL Server using Bulk Insert.

1. Ensure [Python 3](https://www.python.org/downloads/ "Python 3") is installed on your system
1. Extract resultant .7z archive to a known location (C:\Users\username\Desktop\DC=contoso,DC=com)
1. Run [ADConversion.py](https://github.com/aentringer/ADAudit/blob/master/Python/ADConversion.py) in the root directory of the extracted files
    * For ease of use, it is recommended to place the ADConversion.py into a location in your SYSTEM or USER PATH (environment variable). If performed, the script can be more easily called by simply opening a command prompt/shell to the appropriate folder and typing 'ADConversion'. Python executables will also need to be in your PATH for this to work.