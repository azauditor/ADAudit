# Active Directory Audit Scripts

The scripts on this page are designed to query Active Directory to extract data for audit-related purposes. These scripts were designed by the State of Arizona Office of the Auditor General's IT Audit team for internal purposes, but have been released to assist similar government audit shops in Active Directory work.

The scripts on this page were compiled by the Alex Entringer from the work and research of others. I wish to thank the communities around Active Directory, Windows, Python, and PowerShell for making content readily and freely accessible for the benefit of others.

## Intention

These script files were born out of a need to automate and standardize audit work related to Active Directory. Prior to the development of these scripts, the Arizona Auditor General was performing audit work manually using client-agency reported data and Excel. Direct extraction of data has helped increase the accuracy of results and provide more impactful recommendations to audited agencies.

>## PowerShell Disclaimer
>If your systems support it, you should **use PowerShell** instead of the Batch scripts to perform audit related work in Active Directory. The Batch scripts were originally designed at a time when the Arizona Auditor General still frequently encountered 2003 Domain Controllers and Windows XP management computers. Due to a lack of built-in support for PowerShell in those platforms (without manual installation), the scripts on the Batch folder were designed. If you know that the environment you will be auditing can use PowerShell (preferably v3 or greater), or if you are planning on using these in your own environment, **use PowerShell**. The use of PowerShell can also eliminate the need to use Python, which is used in this workflow due to a previous plan to use Linux machines for a portion of this audit work.
>
>We do have a work-in-progress version available in the PowerShell folder, but this should **not** be considered ready for production.
>>
>> ### MAINTAINABILITY
>> These scripts were developed originally by Alex Entringer for the use of the Arizona Auditor General's IT Audit team. While the Batch scripts are robust and stable, Alex Entringer is no longer in an audit role and does not use these on regular basis. Though the Arizona Auditor General's audit teams do still use these scripts, these scripts should be considered deprecated and alternative solutions (**PowerShell**) should be investigated. Changes to the Batch version of the scripts can be requested, and changes/updates will be made as soon as possible, but updates may be slow to never, particularly if the PowerShell version is completed.

## Querying an Active Directory Domain

Multiple steps are required to compile the files used by the scripts provided. This is intended to remind you to think twice before utilizing these scripts over using PowerShell, as well as to reinforce that not all content referenced by these scripts was created by Alex Entringer.

### Batch Version

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

### PowerShell Version

1. Download the file from the 'PowerShell' folder in this repository (.zip) or clone the repository
1. Open PowerShell either directly on server or on a management workstation with RSAT installed.
    * **If running directly on server, you should run from an Adminstrative PowerShell Prompt (Avoids UAC issues).**
1. Import Functions: . .\Get-ADAuditData.ps1
1. 'Get-Help Get-ADAuditData' to read the built-in help

## Cleaning resultant data post-extraction (Batch Version Only)

After the data has been extracted, and you have retreived the .7z archive, the data needs to "cleaned". Due to internal data formats in Active Directory, and the way in which csvde.exe extracts the data, some critical data fields are not in human-readable formats. As a companion to the scripts to extract data, a Python Script was developed to clean up the data, changing data columns into human-readable formats. In addition, the script also changes the data from comma-delimited to pipe-delimited, for easier import into SQL Server using Bulk Insert.

1. Ensure [Python 3](https://www.python.org/downloads/) is installed on your system
1. Extract resultant .7z archive to a known location (C:\Users\username\Desktop\DC=contoso,DC=com)
1. Run [ADConversion.py](https://github.com/aentringer/ADAudit/blob/master/Python/ADConversion.py) in the root directory of the extracted files
    * For ease of use, it is recommended to place the ADConversion.py into a location in your SYSTEM or USER PATH (environment variable). If performed, the script can be more easily called by simply opening a command prompt/shell to the appropriate folder and typing 'ADConversion'. Python executables will also need to be in your PATH for this to work.

## Analyzing the data

Through the use of these scripts, the Arizona Auditor General has gravitated towards using SQL Server for analysis. The primary reasons for this were instabilities with Excel in large AD environments and desire for standardized queries. When importing the data using BULK INSERT, the files can be imported quickly, run against a standard, but flexible set of queries, and can be compared to other relevant data sets.

A .sql file containing sample queries has been uploaded to this repository to show standard checks run by the Arizona Auditor General. These checks are not an exhaustive list of everything that can be reviewed in an Active Directory domain, nor are they necessarily the items that you will want to review for your environment/audit. These are simply the checks that have, over the years, shown to be areas of frequent issues.

If you do not use SQL Server, you can still use the .sql file for inspiration for your own checks, using your own audit tool(s) of choice.

## Providing Suggestions

If you have any suggestions to improve any portion of the workflow provided above, please contact us or submit a pull request so that we can add it to this location. If you have suggestions for other IT Audit areas, not related to Active Directory, please let us know so that we can coordinate to make a central repository for State IT Auditors to share ideas/code/solutions to make audits more efficient or accurate.
