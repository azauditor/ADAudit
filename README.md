# Active Directory Audit Scripts

The scripts on this page are designed to query Active Directory to extract data
for audit-related purposes. These scripts were designed by the Arizona Auditor
General's IT Audit team for internal purposes, but have been released to assist
similar government audit shops in Active Directory work.

The scripts on this page were compiled by from the work and research of others.
We wish to thank the communities around Active Directory, Windows, Python, and
PowerShell for making content readily and freely accessible for the benefit of
others.

## Querying an Active Directory Domain

1. Download the
   [script](https://github.com/azauditor/ADAudit/raw/main/PowerShell/Get-ADAuditData.ps1)
   (right-click "script" and choose 'Save As') from the repository.
   Alternatively, [download a zip file](https://github.com/azauditor/ADAudit/archive/refs/heads/main.zip) to of the entire repository.
2. Open PowerShell either directly on server or on a management workstation with
   RSAT installed.
    - **If running directly on server, you should run from an Administrative
      PowerShell Prompt (Avoids UAC issues).**

    - Use the following command to bring your PowerShell working directory to
      the location where you placed the script (*edit location as appropriate*).

    ``` powershell
        PS C:\> cd C:\Users\EmployeeName\Desktop
    ```
3. Run the script: .\Get-ADAuditData.ps1

   Example:

    ``` powershell
        PS C:\Users\EmployeeName\Desktop> .\Get-ADAuditData.ps1
    ```
4. 'Get-Help .\Get-ADAuditData' to read the built-in help, if you need to use
   the built-in parameters.

    Example:

    ``` powershell
        PS C:\Users\EmployeeName\Desktop> Get-Help .\Get-ADAuditData
    ```

## Analyzing the data

Through the use of these scripts, the Arizona Auditor General has gravitated
towards using SQL Server for analysis. The primary reasons for this were
instabilities with Excel in large AD environments and desire for standardized
queries. The files can be imported quickly, run against a standard, but flexible
set of queries, and can be compared to other relevant data sets.

A [.sql
file](https://github.com/azauditor/ADAudit/blob/main/SQL/SampleQueries.sql)
containing sample queries has been uploaded to this repository to show standard
checks run by the Arizona Auditor General. These checks are not an exhaustive
list of everything that can be reviewed in an Active Directory domain, nor are
they necessarily the items that you will want to review for your
environment/audit. These are simply the checks that have, over the years, shown
to be areas of frequent issues.

If you do not use SQL Server, you can still use the .sql file for inspiration
for your own checks, using your own audit tool(s) of choice.

## Providing Suggestions

If you have any suggestions to improve any portion of the workflow provided
above, please contact us or submit a pull request so that we can add it to this
location. If you have suggestions for other IT Audit areas, not related to
Active Directory, please let us know so that we can coordinate to make a central
repository for State IT Auditors to share ideas/code/solutions to make audits
more efficient or accurate.
