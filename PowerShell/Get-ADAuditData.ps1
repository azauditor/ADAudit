<#
.SYNOPSIS
Queries current AD Domain for data useful for IT Audit Purposes.

.DESCRIPTION
This function will extract key information from Active Directory that can be used to analyze The
management of an AD Domain. It queries information regarding Users, Groups, OUs,
Group Policy Objects, Group Policy Inheritance, Fine Grained Password Policies, Confidential Attributes,
and Trusted Domains.

This does not constitute all of the information that can be reviewed for Active Directory and does not
help determine the actual health of an AD Domain. It is intended for an IT Audit to establish how
well an IT Department is managing specific object types and policies.

.PARAMETER Path
Specifies the path to output the resultant data. Default is the directory where the script file is stored.

.PARAMETER SearchBase
Specifies an Active Directory path to search under. Default is the default naming context of the current
domain.

.EXAMPLE
PS> .\Get-ADAuditData

This example will export AD information to a directory in the current working directory. Verbose output
enabled to visually monitor the script's progress.

.EXAMPLE
PS> .\Get-ADAuditData -Path 'C:\ADExtract'

This example will export AD information to the 'C:\ADExtract' directory.

.EXAMPLE
PS> .\Get-ADAuditData -SearchBase 'OU=Employees,DC=contoso,DC=com'

This example will export AD information under the Employees OU of the contoso.com domain. This searchbase must
be valid in your current domain.

.NOTES
Author: Alex Entringer
#>
[CmdletBinding()]
param (
    [Parameter(Position=0, ValueFromPipeline=$true)]
    [ValidateScript({Test-Path $_ -PathType 'Container'})]
    $Path = $PSScriptRoot,
    [Parameter(Position=1, ValueFromPipeline=$true)]
    $SearchBase = $(Get-ADRootDSE | Select-Object -ExpandProperty 'defaultNamingContext')
)
#Requires -Version 3.0
#Requires -Modules ActiveDirectory, GroupPolicy

function New-ZipFile {
    # http://stackoverflow.com/questions/1153126/how-to-create-a-zip-archive-with-powershell#13302548
    param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        $Path,
        [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_ -PathType 'Container'})]
        $Source
    )
    if ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release).Release -ge 394802) {
        Add-Type -Assembly System.IO.Compression.FileSystem
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
        [System.IO.Compression.ZipFile]::CreateFromDirectory($Source,$Path, $compressionLevel, $true)
    }
}

Function Remove-InvalidFileNameChars {
    # https://stackoverflow.com/questions/23066783/how-to-strip-illegal-characters-before-trying-to-save-filenames#23067832
    param(
        [Parameter(Mandatory=$true,
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String]$Name
    )
    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
    return ($Name -replace $re,'#')
}

function ConvertFrom-UAC {
    param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        $Value
    )
    $uacOptions = @{
        512     = 'Enabled'
        514     = 'Disabled'
        528     = 'Enabled - Locked Out'
        530     = 'Disabled - Locked Out'
        544     = 'Enabled - Password Not Required'
        546     = 'Disabled - Password Not Required'
        560     = 'Enabled - Password Not Required - Locked Out'
        640     = 'Enabled - Encrypted Text Password Allowed'
        2048    = 'Enabled - Interdomain Trust Account'
        2050    = 'Disabled - Interdomain Trust Account'
        2080    = 'Enabled - Interdomain Trust Account - Password Not Required'
        2082    = 'Disabled - Interdomain Trust Account - Password Not Required'
        4096    = 'Enabled - Workstation Trust Account'
        4098    = 'Disabled - Workstation Trust Account'
        4128    = 'Enabled - Workstation Trust Account - Password Not Required'
        4130    = 'Disabled - Workstation Trust Account - Password Not Required'
        8192    = 'Enabled - Server Trust Account'
        8194    = 'Disabled - Server Trust Account'
        66048   = 'Enabled - Password Does Not Expire'
        66050   = 'Disabled - Password Does Not Expire'
        66056   = 'Enabled - Password Does Not Expire - HomeDir Required'
        66064   = 'Enabled - Password Does Not Expire - Locked Out'
        66066   = 'Disabled - Password Does Not Expire - Locked Out'
        66080   = 'Enabled - Password Does Not Expire - Password Not Required'
        66082   = 'Disabled - Password Does Not Expire - Password Not Required'
        66176   = 'Enabled - Password Does Not Expire - Encrypted Text Password Allowed'
        69632   = 'Enabled - Workstation Trust Account - Dont Expire Password'
        131584  = 'Enabled - Majority Node Set (MNS) Account'
        131586  = 'Disabled - Majority Node Set (MNS) Account'
        131600  = 'Enabled - Majority Node Set (MNS) Account - Locked Out'
        197120   = 'Enabled - Majority Note Set (MNS) Account - Password Does Not Expire'
        262656   = 'Enabled - Smartcard Required'
        262658   = 'Disabled - Smartcard Required'
        262690   = 'Disabled - Smartcard Required - Password Not Required'
        328194   = 'Disabled - Smartcard Required - Password Not Required - Password Does Not Expire'
        524800   = 'Enabled - Trusted For Delegation'
        528384   = 'Enabled - Workstation Trust Account - Trusted for Delegation'
        528386   = 'Disabled - Workstation Trust Account - Trusted for Delegation'
        528416   = 'Enabled - Workstation Trust Account - Trusted for Delegation - Password Not Required'
        528418   = 'Disabled - Workstation Trust Account - Trusted for Delegation - Password Not Required'
        532480   = 'Server Trust Account - Trusted For Delegation (Domain Controller)'
        532482   = 'Disabled - Server Trust Account - Trusted For Delegation (Domain Controller)'
        590336   = 'Enabled - Password Does Not Expire - Trusted For Delegation'
        590338   = 'Disabled - Password Does Not Expire - Trusted For Delegation'
        1049088  = 'Enabled - Not Delegated'
        1049090  = 'Disabled - Not Delegated'
        1114624  = 'Enabled - Password Does Not Expire - Not Delegated'
        1114626  = 'Disabled - Password Does Not Expire - Not Delegated'
        1114656  = 'Enabled - Password Not Required - Password Does Not Expire - Not Delegated'
        2097664  = 'Enabled - Use DES Key Only'
        2163200  = 'Enabled - Password Does Not Expire - Use DES Key Only'
        2687488  = 'Enabled - Password Does Not Expire - Trusted For Delegation - Use DES Key Only'
        3211776  = 'Enabled - Password Does Not Expire - Not Delegated - Use DES Key Only'
        4194816  = 'Enabled - PreAuthorization Not Required'
        4260352  = 'Enabled - Password Does Not Expire - PreAuthorization Not Required'
        4260354  = 'Disabled - Password Does Not Expire - PreAuthorization Not Required'
        16781312 = 'Enabled - Workstation Trust Account - Trusted to Authenticate For Delegation'
        16843264 = 'Enabled - Password Does Not Expire - Trusted to Authenticate For Delegation'
        83890176 = 'Enabled - Server Trust Account - Trusted For Delegation - (Read-Only Domain Controller (RODC))'
    }

    if ($null -ne $Value) {
        if ($uacOptions.ContainsKey($Value)) {
            [string]$newValue = $uacOptions[$Value]
        }
        else {
            [string]$newValue = "Unknown User Account Type - $Value"
        }
    }
    else {
        [string]$newValue = "Unknown User Account Type - No Value Available"
    }
    return $newValue
}

function ConvertFrom-UACComputed {
    param(
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        $Value
    )
    $uacComputed = @{
        0          = 'Refer to userAccountControl Field'
        16         = 'Locked Out'
        8388608    = 'Password Expired'
        8388624    = 'Locked Out - Password Expired'
        67108864   = 'Partial Secrets Account'
        2147483648 = 'Use AES Keys'
    }


    if ($null -ne $Value) {
        if ($uacComputed.ContainsKey($Value)) {
            [string]$newValue = $uacComputed[$Value]
        }
        else {
            [string]$newValue = "Unknown User Account Type - $Value"
        }
    }
    else {
        [string]$newValue = "Unknown User Account Type - No Value Available"
    }
    return $newValue
}

function ConvertFrom-PasswordExpiration {
    param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        $Value
    )
    if ($null -ne $Value) {
        if ($Value -eq 0 -or $Value -ge 922337203685477000) {
            [string]$newValue = ''
        }
        else {
            [string]$newValue = (([datetime]::FromFileTime($user.'msDS-UserPasswordExpiryTimeComputed')).ToString("M/d/yyyy h:mm:ss tt"))
        }
    }
    else {
        [string]$newValue = ''
    }
    return $newValue
}

function ConvertFrom-trustDirection {
    param(
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        $Value
    )
    $trustDirect = @{
        0 = 'Disabled (The Trust relationship exists but has been disabled)'
        1 = ('Inbound (One-Way Trust) (TrustING Domain): This is a trusting domain or forest. The other domain ' +
             'or forest has access to the resources of this domain or forest. This domain or forest does not ' +
             'have access to resources that belong to the other domain or forest.')
        2 = ('Outbound (One-Way Trust) (TrustED Domain): This is a trusted domain or forest. This domain or ' +
             'forest has access to resources of the other domain or forest. The other domain or forest does not ' +
             'have access to the resources of this domain or forest.')
        3 = ('Bidirectional (Two-Way Trust): Each domain or forest has access to the resources of the other ' +
             'domain or forest.')
    }

    if ($null -ne $Value) {
        if ($trustDirect.ContainsKey($Value)) {
            $newValue = $trustDirect[$Value]
        }
        else{
            $newValue = "Unknown Trust Direction - $Value"
        }
    }
    else {
        $newValue = "Unknown Trust Direction - No Value Available"
    }
    return $newValue
}

function ConvertFrom-trustType {
    param(
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        $Value
    )
    $trustType = @{
        1 = 'Downlevel Trust (This trust is with a Windows NT Domain (Being External)'
        2 = ('Uplevel (Windows 2000 or later) Trust.  This trust is with an Active Directory domain (being ' +
             'parent-child, root domain, shortcut, external, or forest).')
        3 = 'MIT. This trust is with a (non-Windows) MIT Kerberos Version 5 Realm'
        4 = ('DCE. This trust is with a DCE realm.  DCE refers to Open Groups Distributed Computing Environment ' +
             'specification. This trust type is mainly theoretical)')
    }

    if ($null -ne $Value) {
        if ($trustType.ContainsKey($Value)) {
            [string]$newValue = $trustType[$Value]
        }
        else {
            $newValue = "Unknown Trust Type - $Value"
        }
    }
    else {
        $newValue = "Unknown Trust Type - No Value Available"
    }
    return $newValue
}

function ConvertFrom-trustAttribute {
    param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        $Value
    )
    $trustAttribute = @{
        0 = 'Non-Verifiable Trust (Ask Agency about this!)'
        1 = 'Non-Transitive Trust (Disable transitivity)'
        2 = 'Up-level Trust (Windows 2000 and newer can use link)'
        4 = 'Quarantined Domain External Trust (SID Filtering Enabled)'
        8 = 'Forest Transitive Trust'
        10 = 'Cross-Organizational Trust (Selective Authentication)'
        16 = 'This is a "cross-org" trust with Selective Authentication enabled'
        20 = 'Intra-Forest Trust (Trust within the Forest)'
        32 = 'Forest-Internal'
        40 = 'Treat As External'
        64 = 'This is a forest trust with SIDHistory enabled'
        68 = 'Quarantined Domain (External)'
        80 = 'Trust Attribute Uses RC4 Encryption'
        200 = 'Trust Attribute Cross Organization No TGT Delegation'
        400 = 'PIM (Privleged Identity Management) Trust'
        40000 = 'Tree Parent (Obsolete)'
        80000 = 'Tree Root (Obsolete)'
    }

    if ($null -ne $Value) {
        if ($trustAttribute.ContainsKey($Value)) {
            [string]$newValue = $trustAttribute[$Value]
        }
        else{
            $newValue = "Unknown Trust Attribute - $Value"
        }
    }
    else {
        $newValue = "Unknown Trust Attribute - No Value Available"
    }
    return $newValue
}


#region Check system compatibility
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Warning -Message ('This script does not support PowerShell 2.0. Please run from a system with ' +
        'PowerShell 3.0 or greater.')
    $null = Read-Host 'Press enter to continue...'
    break
}

$sysInfo = Get-CimInstance -ClassName Win32_OperatingSystem

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Warning -Message ("Either you do not have the ActiveDirectory module available on your system, or" +
        "your domain controllers do not have the Active Directory Web Services running.`r`n`r`n")
    if ($sysInfo.ProductType -eq 1) {
        Write-Warning -Message ("Ensure you have the appropriate version of Remote Server Administration Tools " +
            "(RSAT) installed on the workstation where you are running the script.")
        Write-Warning -Message ("Ensure that the domain controller is running Active Directory Web Services " +
            "(ADWS). If your DC is running Server 2003 or 2008, refer to " +
            "<https://www.microsoft.com/en-us/download/details.aspx?id=2852> for the files to install ADWS.")
    }
    if ($sysInfo.ProductType -eq 3) {
        Write-Warning -Message ("Ensure you have the Active Directory Management Tools installed on the member " + 
            "server where you are running the script.")
        Write-Warning -Message ("Ensure that the domain controller is running Active Directory Web Services " +
            "(ADWS). If your DC is running Server 2003 or 2008, refer to " +
            "<https://www.microsoft.com/en-us/download/details.aspx?id=2852> for the files to install ADWS.")
    }
    if ($sysInfo.ProductType -eq 2) {
        Write-Warning -Message ("Ensure that the domain controller is running Active Directory Web Services " +
            "(ADWS). If your DC is running Server 2003 or 2008, refer to " +
            "<https://www.microsoft.com/en-us/download/details.aspx?id=2852> for the files to install ADWS.")
    }
    $null = Read-Host 'Press enter to continue...'
    break
}

if ($sysInfo.ProductType -eq 2) {
    if (-not (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        Write-Warning -Message ("Running script directly on domain controller without running PowerShell as admin.")
        Write-Warning -Message ("Due to UAC restrictions, you may need to run PowerShell as admin ('Run As " +
            "Administrator'), before launching the script.")
        $null = Read-Host 'Press enter to continue...'
        break
    }
    Write-Warning -Message ("It is strongly recommended that you run this script from an administrative " +
    "workstation or jump box member server with RSAT tools, instead of running directly on a domain " +
    "controller.")
}
#endregion Check system compatibility

$domainInfo = Get-ADDomain -Current LocalComputer
$domain = $domainInfo.DistinguishedName

Write-Verbose -Message "Output Path: '$Path\$domain'" -Verbose
Write-Verbose -Message "SearchBase: '$SearchBase'" -Verbose

Write-Verbose -Message "[$(Get-Date -Format G)]  Creating Output Directory" -Verbose
if (Test-Path -Path "$Path\$domain") {
    Remove-Item "$Path\$domain" -Recurse -Force -Confirm
}
New-Item -Path "$Path\$domain" -ItemType Directory | Out-Null
Write-Verbose -Message "[$(Get-Date -Format G)]  Output Directory Created" -Verbose

Write-Verbose -Message "[$(Get-Date -Format G)]  Starting Execution`r`n`r`n" -Verbose
Write-Output "Starting Execution at $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Encoding utf8

Write-Output "Path parameter: '$Path\$domain'" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

Write-Output "SearchBase parameter: '$SearchBase'`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

#region Export Execution OS Information
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting execution OS Information" -Verbose
$PSVersionTable | Out-File -FilePath "$Path\$domain\$env:COMPUTERNAME-sysinfo.txt" -Append -Encoding utf8

Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object 'Description','DNSHostName','Domain','DomainRole',
    'Manufacturer','Model','Name','NumberOfProcessors','PartOfDomain','SystemType',
    @{Name='TotalPhysicalMemoryGB';Expression={[math]::Round($_.TotalPhysicalMemory /1GB)}},
    'UserName','Workgroup' |
    Out-File -FilePath "$Path\$domain\$env:COMPUTERNAME-sysinfo.txt" -Append -Encoding utf8

$sysInfo | Select-Object 'BuildNumber','Caption','FreePhysicalMemory','InstallDate','LastBootUpTime',
    'LocalDateTime','Name','nOSLanguage','OSArchitecture','OSProductSuite','OSType','RegisteredUser',
    'ServicePackMajorVersion','ServicePackMinorVersion','SystemDirectory','SystemDrive','Version',
    'WindowsDirectory' |
    Out-File -FilePath "$Path\$domain\$env:COMPUTERNAME-sysinfo.txt" -Append -Encoding utf8
Write-Verbose -Message "[$(Get-Date -Format G)]  Execution OS Information Exported`r`n`r`n" -Verbose
#endregion Export Execution OS Information

#region Export Domain Information
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Domain Information" -Verbose
Write-Output "Exporting Active Directory Domain Information $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
$domainInfo | Select-Object @{Name='ChildDomains';Expression={$_.ChildDomains -join ';'}},'ComputersContainer',
        'DeletedObjectsContainer','DistinguishedName','DNSRoot','DomainControllersContainer','DomainMode',
        'DomainSID','Forest','InfrastructureMaster','Name','NetBIOSName','ParentDomain','PDCEmulator',
        'RIDMaster','SystemsContainer','UsersContainer' |
    ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$domain\$domain-Info.csv" -Append
Write-Verbose -Message "[$(Get-Date -Format G)]  Active Directory Domain Information Exported`r`n`r`n" -Verbose
Write-Output "Active Directory Domain Information Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
#endregion Export Domain Information

#region Export Domain Controller Information
$dcInfo = Get-ADDomainController -Filter * -Server $($domainInfo.DnsRoot)
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Domain Controller Information" -Verbose
Write-Output "Exporting Active Directory Domain Controller Information $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
$dcInfo | Select-Object 'ComputerObjectDN','DefaultPartition','Domain','Enabled','Forest','HostName',
        'IsGlobalCatalog','IsReadOnly','Name','OperatingSystem','OperatingSystemVersion',
        @{Name='OperationMasterRoles';Expression={$_.'OperationMasterRoles' -join ';'}},'ServerObjectDN',
        'ServerObjectGuid','Site' |
    ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$domain\$domain-domainControllerInfo.csv" -Append
Write-Verbose -Message "[$(Get-Date -Format G)]  Active Directory Domain Controller Information Exported`r`n`r`n" -Verbose
Write-Output "Active Directory Domain Controller Information Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
#endregion Export Domain Controller Information

#region Export Forest Information
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Forest Information" -Verbose
Write-Output "Exporting Active Directory Forest Information $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Get-ADForest -Current LocalComputer |
    Select-Object 'DomainNamingMaster',@{Name='Domains';Expression={$_.Domains -join ';'}},'ForestMode',
        @{Name='GlobalCatalogs';Expression={$_.GlobalCatalogs -join ';'}},'Name','RootDomain','SchemaMaster',
        @{Name='UPNSuffixes';Expression={$_.UPNSuffixes -join ';'}} |
    ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$domain\$domain-ForestInfo.csv" -Append
Write-Verbose -Message "[$(Get-Date -Format G)]  Active Directory Forest Information Exported`r`n`r`n" -Verbose
Write-Output "Active Directory Forest Information Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
#endregion Export Forest Information

#region Export AD Users
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Users" -Verbose
Write-Output "Exporting Active Directory Users $(Get-Date -Format G)" | 
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

$userProps = @('accountExpirationDate','adminCount',
    'assistant','canonicalName','cn','comment','company','controlAccessRights','department','departmentNumber',
    'description','displayName','distinguishedName','division','employeeID','employeeNumber','employeeType',
    'generationQualifier','givenName','info','LastLogonDate','mail','managedObjects','manager','memberOf',
    'middleName','msDS-AllowedToDelegateTo','msDS-PSOApplied','msDS-ResultantPSO','msDS-SourceObjectDN',
    'msDS-User-Account-Control-Computed','msDS-UserPasswordExpiryTimeComputed','name','o','objectSid','ou',
    'PasswordExpired','PasswordLastSet','personalTitle','primaryGroupID','sAMAccountName',
    'seeAlso','servicePrincipalName','sIDHistory','sn','title','uid','uidNumber','userAccountControl',
    'userWorkstations','whenChanged','whenCreated')

$userPropsHeader = @('accountExpirationDate','adminCount',
    'assistant','canonicalName','cn','comment','company','controlAccessRights','department','departmentNumber',
    'description','displayName','distinguishedName','division','employeeID','employeeNumber','employeeType',
    'generationQualifier','givenName','info','LastLogonDate','mail','managedObjects','manager','memberOf',
    'middleName','msDS-AllowedToDelegateTo','msDS-PSOApplied','msDS-ResultantPSO','msDS-SourceObjectDN',
    'msDS-User-Account-Control-Computed','msDS-UserPasswordExpiryTimeComputed','name','o','objectSid','ou',
    'PasswordExpired','PasswordLastSet','personalTitle','primaryGroupID','relativeIdentifier','sAMAccountName',
    'seeAlso','servicePrincipalName','sIDHistory','sn','title','uid','uidNumber','userAccountControl',
    'userWorkstations','whenChanged','whenCreated')

$users = Get-ADUser -SearchBase $SearchBase -Filter * -Properties $userProps

Write-Output "$($users.Count) Active Directory Users Collected $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

$writer = [System.IO.StreamWriter] "$Path\$domain\$domain-Users.csv"
$delimiter = '|'
$eol = "`r`n"

$header = ($userPropsHeader -join $delimiter) + $eol
$writer.Write($header)

$count = 0
foreach ($user in $users) {
    foreach ($managedObject in $user.managedObjects) {
        [string]$managedObjects += ((($managedObject -split (','))[0]) -replace 'CN=' -replace '') + ', '
    }
    foreach ($group in $user.MemberOf) {
        [string]$memberOf += ((($group -split (','))[0]) -replace 'CN=' -replace '') + ', '
    }
    [string]$person = [string]$user.accountExpirationDate + $delimiter +
        $user.'adminCount' + $delimiter +
        $user.'assistant' + $delimiter +
        $(Remove-InvalidFileNameChars($user.canonicalName)) + $delimiter +
        $(Remove-InvalidFileNameChars($user.cn)) + $delimiter +
        $(Remove-InvalidFileNameChars($user.comment)) + $delimiter +
        $user.'company' + $delimiter +
        ($user.controlAccessRights -join ';') + $delimiter +
        $user.'department' + $delimiter +
        ($user.departmentNumber -join ';') + $delimiter +
        $(Remove-InvalidFileNameChars($user.description)) + $delimiter +
        $(Remove-InvalidFileNameChars($user.displayName)) + $delimiter +
        $user.'distinguishedName' + $delimiter +
        $user.'division' + $delimiter +
        $user.'employeeID' + $delimiter +
        $user.'employeeNumber' + $delimiter +
        $user.'employeeType' + $delimiter +
        $user.'generationQualifier' + $delimiter +
        $(Remove-InvalidFileNameChars($user.givenName)) + $delimiter +
        $(Remove-InvalidFileNameChars($user.info)) + $delimiter +
        [string]$user.'LastLogonDate' + $delimiter +
        $user.'mail' + $delimiter +
        $managedObjects + $delimiter +
        $user.'manager' + $delimiter +
        $memberOf + $delimiter +
        $(Remove-InvalidFileNameChars($user.middleName)) + $delimiter +
        ($user.'msDS-AllowedToDelegateTo' -join ';') + $delimiter +
        (($user.'msDS-PSOApplied' -join (";") -replace ",CN=Password Settings Container,CN=System,$domain" -replace "" ) -replace "CN=" -replace "") + $delimiter +
        (($user.'msDS-ResultantPSO' -join (";") -replace ",CN=Password Settings Container,CN=System,$domain" -replace "" ) -replace "CN=" -replace "") + $delimiter +
        $user.'msDS-SourceObjectDN' + $delimiter +
        $(ConvertFrom-UACComputed($user.'msDS-User-Account-Control-Computed')) + $delimiter +
        $(ConvertFrom-PasswordExpiration($user.'msDS-UserPasswordExpiryTimeComputed')) + $delimiter +
        $(Remove-InvalidFileNameChars($user.name)) + $delimiter +
        ($user.o -join ';') + $delimiter +
        $user.'objectSid' + $delimiter +
        ($user.ou -join ';') + $delimiter +
        $user.'PasswordExpired' + $delimiter +
        [string]$user.'PasswordLastSet' + $delimiter +
        $user.'personalTitle' + $delimiter +
        $user.'primaryGroupID' + $delimiter +
        (($user.SID.Value).Split('-')[-1]) + $delimiter +
        $user.'sAMAccountName' + $delimiter +
        ($user.seeAlso -join ';') + $delimiter +
        ($user.servicePrincipalName -join ';') + $delimiter +
        ($user.sIDHistory -join ';') + $delimiter +
        $(Remove-InvalidFileNameChars($user.sn)) + $delimiter +
        $user.'title' + $delimiter +
        ($user.uid -join ';') + $delimiter +
        $user.'uidNumber' + $delimiter +
        $(ConvertFrom-UAC($user.userAccountControl)) + $delimiter +
        $user.'userWorkstations' + $delimiter +
        [string]$user.'whenChanged' + $delimiter +
        [string]$user.'whenCreated' + $eol

    $writer.Write($person)
    Clear-Variable -Name person -ErrorAction SilentlyContinue
    Clear-Variable -Name managedObjects -ErrorAction SilentlyContinue
    Clear-Variable -Name memberOf -ErrorAction SilentlyContinue
    $count += 1
}
$writer.Close()
Clear-Variable -Name users -ErrorAction SilentlyContinue

Write-Verbose -Message "[$(Get-Date -Format G)]  $count Active Directory Users Exported`r`n`r`n" -Verbose
Write-Output "$count Active Directory Users Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Clear-Variable -Name count -ErrorAction SilentlyContinue
#endregion Export AD Users

#region Export AD Groups
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Groups" -Verbose
Write-Output "Exporting Active Directory Groups $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

$groupProps = @('CN','description','displayName','distinguishedName','GroupCategory','GroupScope','ManagedBy',
    'memberOf','msDS-PSOApplied','name','objectSID','sAMAccountName','whenCreated','whenChanged')

$groupPropsHeader = @('CN','description','displayName','distinguishedName','GroupCategory','GroupScope',
    'ManagedBy','memberOf','msDS-PSOApplied','name','objectSID','relativeIdentifier','sAMAccountName',
    'whenCreated','whenChanged')

$groups = Get-ADGroup -SearchBase $SearchBase -Filter * -Properties $groupProps

Write-Output "$($groups.Count) Active Directory Groups Collected $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

$writer = [System.IO.StreamWriter] "$Path\$domain\$domain-Groups.csv"

$header = ($groupPropsHeader -join $delimiter) + $eol
$writer.Write($header)

$count = 0
foreach ($group in $groups) {
    foreach ($item in $group.MemberOf) {
        [string]$memberOf += ((($item -split (','))[0]) -replace 'CN=' -replace '') + ', '
    }
    [string]$groupItem = $(Remove-InvalidFileNameChars($group.'CN')) + $delimiter +
        $(Remove-InvalidFileNameChars($group.'description')) + $delimiter +
        $(Remove-InvalidFileNameChars($group.'displayName')) + $delimiter +
        $group.'distinguishedName' + $delimiter +
        $group.'GroupCategory' + $delimiter +
        $group.'GroupScope' + $delimiter +
        $group.'ManagedBy' + $delimiter +
        $memberOf + $delimiter +
        (($group.'msDS-PSOApplied' -join (";") -replace ",CN=Password Settings Container,CN=System,$domain" -replace "" ) -replace "CN=" -replace "") + $delimiter +
        $(Remove-InvalidFileNameChars($group.'name')) + $delimiter +
        $group.'objectSid' + $delimiter +
        ($group.SID.Value).Split('-')[-1] + $delimiter +
        $group.'sAMAccountName' + $delimiter +
        $group.'whenChanged' + $delimiter +
        $group.'whenCreated' + $eol

    $writer.Write($groupItem)
    Clear-Variable -Name groupItem -ErrorAction SilentlyContinue
    Clear-Variable -Name memberOf -ErrorAction SilentlyContinue
    $count += 1
}
$writer.Close()
Clear-Variable -Name groups -ErrorAction SilentlyContinue

Write-Verbose -Message "[$(Get-Date -Format G)]  $count Active Directory Groups Exported`r`n`r`n" -Verbose
Write-Output "$count Active Directory Groups Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Clear-Variable -Name count -ErrorAction SilentlyContinue
#endregion Export AD Groups

#region Export AD Computers
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Computer Accounts" -Verbose
Write-Output "Exporting Computer Accounts $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

$computerProps = @('cn','description','displayName','distinguishedName','LastLogonDate','name','objectSid',
    'operatingSystem','operatingSystemServicePack','operatingSystemVersion','primaryGroupID','PasswordLastSet',
    'userAccountControl','whenCreated','whenChanged')

$computers = Get-ADComputer -SearchBase $SearchBase -Filter * -Properties $computerProps

Write-Output "$($Computers.Count) Active Directory Computers Collected $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

$writer = [System.IO.StreamWriter] "$Path\$domain\$domain-Computers.csv"

$header = ($computerProps -join $delimiter) + $eol
$writer.Write($header)

$count = 0
foreach ($computer in $computers) {
    [string]$computerItem = $computer.'cn' + $delimiter +
        $(Remove-InvalidFileNameChars($computer.'description')) + $delimiter +
        $(Remove-InvalidFileNameChars($computer.'displayName')) + $delimiter +
        $computer.'distinguishedName' + $delimiter +
        [string]$computer.'LastLogonDate' + $delimiter +
        $(Remove-InvalidFileNameChars($computer.'name')) + $delimiter +
        $computer.'objectSid' + $delimiter +
        $computer.'operatingSystem' + $delimiter +
        $computer.'operatingSystemServicePack' + $delimiter +
        $computer.'operatingSystemVersion' + $delimiter +
        $computer.'primaryGroupID' + $delimiter +
        [string]$computer.'PasswordLastSet' + $delimiter +
        $(ConvertFrom-UAC($computer.'userAccountControl')) + $delimiter +
        [string]$computer.'whenChanged' + $delimiter +
        [string]$computer.'whenCreated' + $eol

    $writer.Write($computerItem)
    Clear-Variable -Name computerItem -ErrorAction SilentlyContinue
    $count += 1
}
$writer.Close()
Clear-Variable -Name computers -ErrorAction SilentlyContinue

Write-Verbose -Message "[$(Get-Date -Format G)]  $count Active Directory Computers Exported`r`n`r`n" -Verbose
Write-Output "$count Active Directory Computers Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Clear-Variable -Name count -ErrorAction SilentlyContinue
#endregion Export AD Computers

#region Export AD OUs
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Organizational Units" -Verbose
Write-Output "Exporting Active Directory Organizational Units $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

$ouProps = @('CanonicalName','Description','DisplayName','DistinguishedName','ManagedBy','Name','whenChanged',
    'whenCreated')

$ous = Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * -Properties $ouProps

Write-Output "$($ous.Count) Active Directory OUs Collected $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

$writer = [System.IO.StreamWriter] "$Path\$domain\$domain-OUs.csv"

$header = ($ouProps -join $delimiter) + $eol
$writer.Write($header)

foreach ($ou in $ous) {
    [string]$ouItem = $(Remove-InvalidFileNameChars($ou.canonicalName)) + $delimiter +
        $(Remove-InvalidFileNameChars($ou.description)) + $delimiter +
        $(Remove-InvalidFileNameChars($ou.displayName)) + $delimiter +
        $ou.'distinguishedName' + $delimiter +
        $ou.'ManagedBy' + $delimiter +
        $(Remove-InvalidFileNameChars($ou.name)) + $delimiter +
        $ou.'whenChanged' + $delimiter +
        $ou.'whenCreated' + $eol

    $writer.Write($ouItem)
    Clear-Variable -Name ouItem -ErrorAction SilentlyContinue
    $count += 1
}
$writer.Close()
Clear-Variable -Name ous -ErrorAction SilentlyContinue

Write-Verbose -Message "[$(Get-Date -Format G)]  $count Active Directory OUs Exported`r`n`r`n" -Verbose
Write-Output "$count Active Directory OUs Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Clear-Variable -Name count -ErrorAction SilentlyContinue
#endregion Export AD OUs

#region Export AD GPOs
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Group Policy Objects" -Verbose
Write-Output "Exporting Active Directory Group Policy Objects $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
New-Item -Path "$Path\$domain\GroupPolicy" -ItemType Directory | Out-Null
New-Item -Path "$Path\$domain\GroupPolicy\Reports" -ItemType Directory | Out-Null

$gpos = Get-GPO -All
Write-Output "$($gpos.Count) Active Directory GPOs Collected $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

$count = 0
foreach ($gpo in $gpos) {
    $GPOName = Remove-InvalidFileNameChars($gpo.'DisplayName')
    Get-GPOReport -Guid $gpo.'id' -ReportType 'HTML' -Path "$Path\$domain\GroupPolicy\Reports\$GPOName.html"
    $count += 1
}
Clear-Variable -Name gpos -ErrorAction SilentlyContinue

Write-Verbose -Message "[$(Get-Date -Format G)]  $count Active Directory Group Policy Objects Exported`r`n`r`n" -Verbose
Write-Output "$count Active Directory Group Policy Objects Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Clear-Variable -Name count -ErrorAction SilentlyContinue
#endregion Export AD GPOs

#region Export AD GPO Inheritance
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory GPO Inheritance Configurations" -Verbose
Write-Output "Exporting Active Directory GPO Inheritance Configurations $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
New-Item -Path "$Path\$domain\GroupPolicy\Inheritance" -ItemType Directory | Out-Null
$domainGPI = Get-GPInheritance -Target $domain
$domainGPI | Select-Object Name,ContainerType,Path,GpoInheritanceBlocked | Format-List |
    Out-File -FilePath "$Path\$domain\GroupPolicy\Inheritance\$domain.txt"
$domainGPI | Select-Object -ExpandProperty InheritedGpoLinks |
    Out-File -FilePath "$Path\$domain\GroupPolicy\Inheritance\$domain.txt" -Append
Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * | ForEach-Object {
    $FileName = Remove-InvalidFileNameChars($_.DistinguishedName)
    $CurrentGPI = Get-GPInheritance -Target $_.DistinguishedName
    $CurrentGPI | Select-Object Name,ContainerType,Path,GpoInheritanceBlocked | Format-List |
        Out-File -FilePath "$Path\$domain\GroupPolicy\Inheritance\$FileName.txt"
    $CurrentGPI | Select-Object -ExpandProperty InheritedGpoLinks |
        Out-File -FilePath "$Path\$domain\GroupPolicy\Inheritance\$FileName.txt" -Append
}

# Count Inheritance files for reporting
$gpos = (Get-ChildItem -Path "$Path\$domain\GroupPolicy\Inheritance" -Filter *.txt).Count

Write-Verbose -Message "[$(Get-Date -Format G)]  $gpos Active Directory GPO Inheritance Configurations Exported`r`n`r`n" -Verbose
Write-Output "$gpos Active Directory GPO Inheritance Configurations Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Clear-Variable -Name gpos -ErrorAction SilentlyContinue
#endregion Export AD GPO Inheritance

#region Export AD OU ACLs
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Organizational Unit Access Control Lists" -Verbose
Write-Output "Exporting Active Directory Organizational Unit Access Control Lists $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
New-Item -Path "$Path\$domain\OU" -ItemType Directory | Out-Null
New-Item -Path "$Path\$domain\OU\ACLs" -ItemType Directory | Out-Null
# Special Thanks to Ashley McGlone for the heavy lifting here
# https://blogs.technet.microsoft.com/ashleymcglone/2013/03/25/active-directory-ou-permissions-report-free-powershell-script-download/
# https://gallery.technet.microsoft.com/Active-Directory-OU-1d09f989

# Build a lookup hash table that holds all of the string names of the
# ObjectType GUIDs referenced in the security descriptors.
# See the Active Directory Technical Specifications:
#  3.1.1.2.3 Attributes
#    http://msdn.microsoft.com/en-us/library/cc223202.aspx
#  3.1.1.2.3.3 Property Set
#    http://msdn.microsoft.com/en-us/library/cc223204.aspx
#  5.1.3.2.1 Control Access Rights
#    http://msdn.microsoft.com/en-us/library/cc223512.aspx
#  Working with GUID arrays
#    http://blogs.msdn.com/b/adpowershell/archive/2009/09/22/how-to-find-extended-rights-that-apply-to-a-schema-class-object.aspx
# Hide the errors for a couple duplicate hash table keys.
$schemaIDGUID = @{}
### NEED TO RECONCILE THE CONFLICTS ###
$EAP = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID |
    ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |
    ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}
$ErrorActionPreference = $EAP

if ($SearchBase -eq $(Get-ADRootDSE | Select-Object 'defaultNamingContext')) {
    $OUs  = @(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
    $OUs += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
    $OUs += Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -SearchScope OneLevel -LDAPFilter '(objectClass=container)' | Select-Object -ExpandProperty DistinguishedName
}
else {
    $OUs = @(Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * | 
        Select-Object -ExpandProperty DistinguishedName)
}

ForEach ($OU in $OUs) {
    $FileName = Remove-InvalidFileNameChars($OU)
    Get-Acl -Path "AD:\$OU" | Select-Object -ExpandProperty Access |
        Select-Object @{name='organizationalUnit';expression={$OU}},
            @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}},
            @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}},* |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\OU\ACLs\$FileName.csv" -Append
}

# Count OU ACL files for reporting
$ouCount = (Get-ChildItem -Path "$Path\$domain\OU\ACLs" -Filter *.csv).Count

Write-Verbose -Message "[$(Get-Date -Format G)]  $ouCount Active Directory Organizational Unit Access Control Lists Exported`r`n`r`n" -Verbose
Write-Output "$ouCount Active Directory Organizational Unit Access Control Lists Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Clear-Variable -Name ouCount -ErrorAction SilentlyContinue
#endregion Export AD OU ACLs

#region Export AD Confidentiality Bit
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Confidentiality Bit Details" -Verbose
Write-Output "Exporting Active Directory Confidentiality Bit Details $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$domain" -LDAPFilter '(searchFlags:1.2.840.113556.1.4.803:=128)' |
    Select-Object 'DistinguishedName','Name' |
    ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$domain\$domain-confidentialBit.csv" -Append

# Count Rows for reporting purposes
$rows = 0
$reader = New-Object IO.StreamReader "$Path\$domain\$domain-confidentialBit.csv"
while ($null -ne $reader.ReadLine()) { $rows++ }
$reader.Close()
$rows--
if ($rows -lt 0) {
    $rows = 0
}

Write-Verbose -Message "[$(Get-Date -Format G)]  $rows Active Directory Confidential Bit Details Exported`r`n`r`n" -Verbose
Write-Output "$rows Active Directory Confidential Bit Details Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Clear-Variable -Name rows -ErrorAction SilentlyContinue
#endregion Export AD Confidentiality Bit

#region Export AD Default Domain Password Policy
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Default Domain Password Policy" -Verbose
Write-Output "Exporting Active Directory Default Domain Password Policy $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Get-ADDefaultDomainPasswordPolicy | Select-Object -Property 'ComplexityEnabled','DistinguishedName',
    'LockoutDuration','LockoutObservationWindow','LockoutThreshold','MaxPasswordAge','MinPasswordAge',
    'MinPasswordLength','PasswordHistoryCount','ReversibleEncryptionEnabled' |
    ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', '' } |
    Out-File -FilePath "$Path\$domain\$domain-defaultDomainPasswordPolicy.csv" -Append
Write-Verbose -Message "[$(Get-Date -Format G)]  Active Directory Default Domain Password Policy Exported`r`n`r`n" -Verbose
Write-Output "Active Directory Default Domain Password Policy Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
#endregion Export AD Default Domain Password Policy

#region Export AD FGPP
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Fine Grained Password Policies" -Verbose
Write-Output "Exporting Active Directory Fine Grained Password Policies $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Get-ADFineGrainedPasswordPolicy -Filter * -Properties 'appliesTo','ComplexityEnabled','DistinguishedName',
    'LockoutDuration','LockoutObservationWindow','LockoutThreshold','MaxPasswordAge','MinPasswordAge',
    'MinPasswordLength','Name','PasswordHistoryCount','Precedence','ReversibleEncryptionEnabled' |
    Select-Object 'ComplexityEnabled','DistinguishedName','LockoutDuration','LockoutObservationWindow',
        'LockoutThreshold','MaxPasswordAge','MinPasswordAge','MinPasswordLength',
        @{Name='msDS-PSOAppliesTo';Expression={(($_.appliesTo -split (",") | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},
        'Name','PasswordHistoryCount','Precedence','ReversibleEncryptionEnabled' |
    ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', '' } |
    Out-File -FilePath "$Path\$domain\$domain-fgppDetails.csv" -Append

# Count Rows for reporting
$rows = 0
$reader = New-Object IO.StreamReader "$Path\$domain\$domain-fgppDetails.csv"
while ($null -ne $reader.ReadLine()) { $rows++ }
$reader.Close()
$rows--
if ($rows -lt 0) {
    $rows = 0
}

Write-Verbose -Message "[$(Get-Date -Format G)]  $rows Active Directory Fine Grained Password Policies Exported`r`n`r`n" -Verbose
Write-Output "$rows Active Directory Fine Grained Password Policies Exported $(Get-Date -Format G)`r`n" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
Clear-Variable -Name rows -ErrorAction SilentlyContinue
#endregion Export AD FGPP

#region Export AD Domain Trusts
Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Domain Trusts" -Verbose
Write-Output "Exporting Active Directory Domain Trusts $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {
        Get-ADTrust -Filter * -Properties 'CanonicalName', 'CN', 'Created', 'createTimeStamp', 'Deleted',
        'Description', 'DisallowTransivity','DisplayName', 'DistinguishedName', 'flatName', 'ForestTransitive',
        'instanceType', 'IntraForest', 'isCriticalSystemObject', 'isDeleted', 'isTreeParent', 'IsTreeRoot',
        'LastKnownParent', 'Modified', 'modifyTimeStamp', 'Name', 'ObjectCategory', 'ObjectClass',
        'ObjectGUID', 'ProtectedFromAccidentalDeletion', 'sDRightsEffective', 'securityIdentifier',
        'SelectiveAuthentication', 'showInAdvancedViewOnly', 'SIDFilteringForestAware',
        'SIDFilteringQuarantined', 'Source', 'Target', 'TGTDelegation', 'TrustAttributes', 'trustDirection',
        'TrustingPolicy', 'trustPartner', 'trustPosixOffset', 'TrustType', 'UplevelOnly', 'UsesAESKeys',
        'UsesRC4Encryption', 'uSNChanged', 'uSNCreated', 'whenChanged', 'whenCreated' |
            Select-Object 'CanonicalName', 'CN', 'Created', 'createTimeStamp', 'Deleted', 'Description',
            'DisallowTransivity', 'DisplayName', 'DistinguishedName', 'flatName', 'ForestTransitive',
            'instanceType', 'IntraForest', 'isCriticalSystemObject', 'isDeleted', 'isTreeParent', 'IsTreeRoot',
            'LastKnownParent', 'Modified', 'modifyTimeStamp', 'Name', 'ObjectCategory', 'ObjectClass',
            'ObjectGUID', 'ProtectedFromAccidentalDeletion', 'sDRightsEffective', 'securityIdentifier',
            'SelectiveAuthentication', 'showInAdvancedViewOnly', 'SIDFilteringForestAware',
            'SIDFilteringQuarantined', 'Source', 'Target', 'TGTDelegation', 
            @{Name='TrustAttributes';Expression={(ConvertFrom-trustAttribute($_.TrustAttributes))}},
            @{Name='trustDirection';Expression={(ConvertFrom-trustDirection($_.trustDirection))}},
            'TrustingPolicy', 'trustPartner', 'trustPosixOffset', 
            @{Name='TrustType';Expression={(ConvertFrom-trustType($_.TrustType))}},
            'UplevelOnly', 'UsesAESKeys', 'UsesRC4Encryption', 'uSNChanged', 'uSNCreated', 'whenChanged',
            'whenCreated' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\$domain-trustedDomains.csv" -Append

    # Count Rows for reporting
    $rows = 0
    $reader = New-Object IO.StreamReader "$Path\$domain\$domain-trustedDomains.csv"
    while ($null -ne $reader.ReadLine()) { $rows++ }
    $reader.Close()
    $rows--
    if ($rows -lt 0) {
        $rows = 0
    }
    Write-Verbose -Message "[$(Get-Date -Format G)]  $rows Active Directory Domain Trusts Exported`r`n`r`n" -Verbose
    Write-Output "$rows Active Directory Domain Trusts Exported $(Get-Date -Format G)`r`n" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    Clear-Variable -Name rows -ErrorAction SilentlyContinue
}
else {
    Write-Warning -Message "[$(Get-Date -Format G)]  Get-ADTrust cmdlet Not Available"
    Write-Output "WARNING: Get-ADTrust Not Available $(Get-Date -Format G)" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Domain Trusts with netdom" -Verbose
    & netdom query trust > "$Path\$domain\$domain-trustedDomains-netdom.txt"
    Write-Verbose -Message "[$(Get-Date -Format G)]  Active Directory Domain Trusts Exported with netdom`r`n`r`n" -Verbose
    Write-Output "$rows Active Directory Domain Trusts Exported via netdom $(Get-Date -Format G)`r`n" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
}
#endregion Export AD Domain Trusts

Write-Verbose -Message "[$(Get-Date -Format G)]  Finished Execution`r`n`r`n" -Verbose
Write-Output "Finished Execution at $(Get-Date -Format G)" |
    Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8

if ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release -ErrorAction SilentlyContinue).Release -ge 394802) {
    Write-Verbose -Message "[$(Get-Date -Format G)]  Compressing Output Data to Zip File" -Verbose
    New-ZipFile -Path "$Path\$domain.zip" -Source "$Path\$domain"
    Write-Verbose -Message "[$(Get-Date -Format G)]  Output Data Compressed to Zip File" -Verbose
}
else {
    Write-Verbose -Message "[$(Get-Date -Format G)]  Cannot Compress Output Data to Zip File due to insufficient .NET Version" -Verbose
    Write-Output ".NET framework 4 unavailable - Not compressing output $(Get-Date -Format G)" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
}
$null = Read-Host 'Press enter to continue...'
