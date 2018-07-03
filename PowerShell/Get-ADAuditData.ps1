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
        [String]$Name
    )
    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
    return ($Name -replace $re)
}

function ConvertFrom-UAC {
    param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
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

    if ($uacOptions.ContainsKey($Value)) {
        $newValue = $uacOptions[$Value]
    }
    else {
        $newValue = 'Unknown User Account Type'
    }
    return $newValue
}

function ConvertFrom-UACComputed {
    param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
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

    if ($uacComputed.ContainsKey($Value)) {
        $newValue = $uacComputed[$Value]
    }
    else {
        $newValue = 'Unknown User Account Type'
    }
    return $newValue
}

function ConvertFrom-trustDirection {
    param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        $Value
    )
    $trustDirect = @{
        0 = 'Disabled (The Trust relationship exists but has been disabled)'
        1 = 'Inbound (One-Way Trust) (TrustING Domain): This is a trusting domain or forest. The other domain or forest has access to the resources of this domain or forest. This domain or forest does not have access to resources that belong to the other domain or forest.'
        2 = 'Outbound (One-Way Trust) (TrustED Domain): This is a trusted domain or forest. This domain or forest has access to resources of the other domain or forest. The other domain or forest does not have access to the resources of this domain or forest.'
        3 = 'Bidirectional (Two-Way Trust): Each domain or forest has access to the resources of the other domain or forest.'
    }

    if ($trustDirect.ContainsKey($Value)) {
        $newValue = $trustDirect[$Value]
    }
    else{
        $newValue = 'Unknown Trust Direction'
    }
    return $newValue
}

function ConvertFrom-trustType {
    param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        $Value
    )
    $trustType = @{
        1 = 'Downlevel Trust (This trust is with a Windows NT Domain (Being External)'
        2 = 'Uplevel (Windows 2000 or later) Trust.  This trust is with an Active Directory domain (being parent-child, root domain, shortcut, external, or forest).'
        3 = 'MIT. This trust is with a (non-Windows) MIT Kerberos Version 5 Realm'
        4 = 'DCE. This trust is with a DCE realm.  DCE refers to Open Groups Distributed Computing Environment specification. This trust type is mainly theoretical)'
    }

    if ($trustType.ContainsKey($Value)) {
        $newValue = $trustType[$Value]
    }
    else{
        $newValue = 'Unknown Trust Type'
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

    if ($trustAttribute.ContainsKey($Value)) {
        $newValue = $trustAttribute[$Value]
    }
    else{
        $newValue = 'Unknown Trust Attribute'
    }
    return $newValue
}

function Get-ADAuditData {
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
    Specifies the path to output the resultant data. Default is the executing users desktop directory.

    .PARAMETER SearchBase
    Specifies an Active Directory path to search under. Default is the default naming context of the current
    domain.

    .EXAMPLE
    PS> Get-ADAuditData

    This example will export AD information to a directory in the current working directory. Verbose output
    enabled to visually monitor the script's progress.

    .EXAMPLE
    PS> Get-ADAuditData -Path 'C:\ADExtract'

    This example will export AD information to the 'C:\ADExtract' directory.

    .EXAMPLE
    PS> Get-ADAuditData -SearchBase 'OU=Employees,DC=contoso,DC=com'

    This example will export AD information under the Employees OU of the contoso.com domain. This searchbase must
    be valid in your current domain.

    .NOTES
    Author: Alex Entringer
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_ -PathType 'Container'})]
        $Path = "$env:USERPROFILE\Desktop",
        [Parameter(Position=1, ValueFromPipeline=$true)]
        $SearchBase = $(Get-ADRootDSE | Select-Object -ExpandProperty 'defaultNamingContext')
    )
    #Requires -Version 3.0
    #Requires -Modules ActiveDirectory, GroupPolicy

    if ($PSVersionTable.PSVersion.Major -lt 3) {
        Write-Warning -Message 'This function does not support PowerShell 2.0. Please run from a system with PowerShell 3.0 or greater.'
        break
    }

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
    Get-ADUser -SearchBase $SearchBase -Filter * -Properties 'accountExpirationDate','adminCount','assistant',
        'canonicalName','cn','comment','company','controlAccessRights','department','departmentNumber',
        'description','displayName','distinguishedName','division','employeeID','employeeNumber','employeeType',
        'generationQualifier','givenName','info','LastLogonDate','mail','managedObjects','manager','memberOf',
        'middleName','msDS-AllowedToDelegateTo','msDS-PSOApplied','msDS-ResultantPSO','msDS-SourceObjectDN',
        'msDS-User-Account-Control-Computed','msDS-UserPasswordExpiryTimeComputed','name','o','objectSid','ou',
        'PasswordLastSet','PasswordExpired','personalTitle','primaryGroupID','sAMAccountName',
        'seeAlso','servicePrincipalName','sIDHistory','sn','title','uid','uidNumber','userAccountControl',
        'userWorkstations','whenChanged','whenCreated' |
        Select-Object 'accountExpirationDate','adminCount','assistant',
            @{Name='canonicalName';Expression={Remove-InvalidFileNameChars($_.canonicalName)}},
            @{Name='cn';Expression={Remove-InvalidFileNameChars($_.cn)}},
            @{Name='comment';Expression={Remove-InvalidFileNameChars($_.comment)}},
            'company',
            @{Name='controlAccessRights';Expression={$_.controlAccessRights -join ';'}},
            'department',
            @{Name='departmentNumber';Expression={$_.departmentNumber -join ';'}},
            @{Name='description';Expression={Remove-InvalidFileNameChars($_.description)}},
            @{Name='displayName';Expression={Remove-InvalidFileNameChars($_.displayName)}},
            'distinguishedName','division','employeeID','employeeNumber','employeeType','generationQualifier',
            @{Name='givenName';Expression={Remove-InvalidFileNameChars($_.givenName)}},
            @{Name='info';Expression={Remove-InvalidFileNameChars($_.info)}},
            'mail',
            @{Name='managedObjects';Expression={(($_.managedObjects -split (",") | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},
            'manager',
            @{Name='memberOf';Expression={(($_.memberof -split (",") | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},
            @{Name='middleName';Expression={Remove-InvalidFileNameChars($_.middleName)}},
            @{Name='msDS-AllowedToDelegateTo';Expression={$_.'msDS-AllowedToDelegateTo' -join ';'}},
            @{Name="msDS-PSOApplied";Expression={((($_.'msDS-PSOApplied' -join (";"))) -replace ",CN=Password Settings Container,CN=System,$domain" -replace "" ) -replace "CN=" -replace "" }},
            @{Name="msDS-ResultantPSO";Expression={((($_.'msDS-ResultantPSO' -join (";"))) -replace ",CN=Password Settings Container,CN=System,$domain" -replace "" ) -replace "CN=" -replace "" }},
            'msDS-SourceObjectDN',
            @{Name='msDS-User-Account-Control-Computed';Expression={(ConvertFrom-UACComputed($_.'msDS-User-Account-Control-Computed'))}},
            @{Name='msDS-UserPasswordExpiryTimeComputed';Expression={([datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed')).ToString("M/d/yyyy h:mm:ss tt")}},
            'LastLogonDate',
            @{Name='name';Expression={Remove-InvalidFileNameChars($_.name)}},
            @{Name='o';Expression={$_.o -join ';'}},'objectSid',
            @{Name='ou';Expression={$_.ou -join ';'}},'PasswordLastSet','PasswordExpired',
            'personalTitle','primaryGroupID','sAMAccountName',
            @{Name='relativeIdentifier';Expression={($_.SID.Value).Split('-')[-1]}},
            @{Name='seeAlso';Expression={$_.seeAlso -join ';'}},
            @{Name='servicePrincipalName';Expression={$_.servicePrincipalName -join ';'}},
            @{Name='sIDHistory';Expression={$_.sIDHistory -join ';'}},
            @{Name='sn';Expression={Remove-InvalidFileNameChars($_.sn)}},
            'title',
            @{Name='uid';Expression={$_.uid -join ';'}},'uidNumber',
            @{Name='userAccountControl';Expression={(ConvertFrom-UAC($_.userAccountControl))}},'userWorkstations',
            'whenChanged','whenCreated' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', '' } |
        Out-File -FilePath "$Path\$domain\$domain-Users.csv" -Append

    # Count Rows for reporting purposes
    $rows = 0
    $reader = New-Object IO.StreamReader "$Path\$domain\$domain-Users.csv"
    while ($reader.ReadLine() -ne $null) { $rows++ }
    $reader.Close()
    $rows--
    if ($rows -lt 0) {
        $rows = 0
    }

    Write-Verbose -Message "[$(Get-Date -Format G)]  $rows Active Directory Users Exported`r`n`r`n" -Verbose
    Write-Output "$rows Active Directory Users Exported $(Get-Date -Format G)`r`n" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    $rows = $null
    #endregion Export AD Users

    #region Export AD Groups
    Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Groups" -Verbose
    Write-Output "Exporting Active Directory Groups $(Get-Date -Format G)" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    Get-ADGroup -SearchBase $SearchBase -Filter * -Properties 'distinguishedName','sAMAccountName','CN',
        'displayName','name','description','GroupCategory','GroupScope','ManagedBy', 'memberOf','objectSID',
        'msDS-PSOApplied','whenCreated','whenChanged' |
        Select-Object 'distinguishedName',
            'sAMAccountName',
            @{Name='CN';Expression={Remove-InvalidFileNameChars($_.CN)}},
            @{Name='displayName';Expression={Remove-InvalidFileNameChars($_.displayName)}},
            @{Name='name';Expression={Remove-InvalidFileNameChars($_.name)}},
            @{Name='description';Expression={Remove-InvalidFileNameChars($_.description)}},
            'GroupCategory','GroupScope','ManagedBy',
            @{Name="memberOf";Expression={(($_.memberof -split (",") | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},
            'objectSID',
            @{Name="msDS-PSOApplied";Expression={((($_.'msDS-PSOApplied' -join (";"))) -replace ",CN=Password Settings Container,CN=System,$domain" -replace "" ) -replace "CN=" -replace "" }},
            @{Name='relativeIdentifier';Expression={($_.SID.Value).Split('-')[-1]}},'whenCreated','whenChanged' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\$domain-Groups.csv" -Append

    # Count Rows for reporting
    $rows = 0
    $reader = New-Object IO.StreamReader "$Path\$domain\$domain-Groups.csv"
    while ($reader.ReadLine() -ne $null) { $rows++ }
    $reader.Close()
    $rows--
    if ($rows -lt 0) {
        $rows = 0
    }

    Write-Verbose -Message "[$(Get-Date -Format G)]  $rows Active Directory Groups Exported`r`n`r`n" -Verbose
    Write-Output "$rows Active Directory Groups Exported $(Get-Date -Format G)`r`n" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    $rows = $null
    #endregion Export AD Groups

    #region Export AD Computers
    Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Computer Accounts" -Verbose
    Write-Output "Exporting Computer Accounts $(Get-Date -Format G)" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    Get-ADComputer -SearchBase $SearchBase -Filter * -Properties 'cn','description','displayName',
        'distinguishedName','LastLogonDate','name','objectSid','operatingSystem','operatingSystemServicePack',
        'operatingSystemVersion','primaryGroupID','PasswordLastSet','userAccountControl','whenCreated',
        'whenChanged' |
        Select-Object 'cn',
        @{Name='description';Expression={Remove-InvalidFileNameChars($_.description)}},
        @{Name='displayName';Expression={Remove-InvalidFileNameChars($_.displayName)}},
        'distinguishedName','LastLogonDate',
        @{Name='name';Expression={Remove-InvalidFileNameChars($_.name)}},
        'objectSid','operatingSystem','operatingSystemServicePack','operatingSystemVersion','primaryGroupID',
        'PasswordLastSet',
        @{Name='userAccountControl';Expression={(ConvertFrom-UAC($_.userAccountControl))}},
        'whenCreated','whenChanged' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\$domain-Computers.csv" -Append

    # Count Rows for reporting
    $rows = 0
    $reader = New-Object IO.StreamReader "$Path\$domain\$domain-Computers.csv"
    while ($reader.ReadLine() -ne $null) { $rows++ }
    $reader.Close()
    $rows--
    if ($rows -lt 0) {
        $rows = 0
    }

    Write-Verbose -Message "[$(Get-Date -Format G)]  $rows Active Directory Computers Exported`r`n`r`n" -Verbose
    Write-Output "$rows Active Directory Computers Exported $(Get-Date -Format G)`r`n" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    #endregion Export AD Computers

    #region Export AD OUs
    Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Organizational Units" -Verbose
    Write-Output "Exporting Active Directory Organizational Units $(Get-Date -Format G)" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * -Properties 'DistinguishedName','Name',
        'CanonicalName','DisplayName','Description','whenCreated','whenChanged','ManagedBy' |
        Select-Object 'DistinguishedName','Name','CanonicalName','DisplayName','Description','whenCreated',
        'whenChanged','ManagedBy' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\$domain-OUs.csv" -Append

    # Count Rows for reporting
    $rows = 0
    $reader = New-Object IO.StreamReader "$Path\$domain\$domain-OUs.csv"
    while ($reader.ReadLine() -ne $null) { $rows++ }
    $reader.Close()
    $rows--
    if ($rows -lt 0) {
        $rows = 0
    }

    Write-Verbose -Message "[$(Get-Date -Format G)]  $rows Active Directory OUs Exported`r`n`r`n" -Verbose
    Write-Output "$rows Active Directory OUs Exported $(Get-Date -Format G)`r`n" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    $rows = $null
    #endregion Export AD OUs

    #region Export AD GPOs
    Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Group Policy Objects" -Verbose
    Write-Output "Exporting Active Directory Group Policy Objects $(Get-Date -Format G)" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    New-Item -Path "$Path\$domain\GroupPolicy" -ItemType Directory | Out-Null
    New-Item -Path "$Path\$domain\GroupPolicy\Reports" -ItemType Directory | Out-Null
    Get-GPO -All | ForEach-Object {
        $GPOName = Remove-InvalidFileNameChars($_.DisplayName)
        Get-GPOReport -Guid $_.id -ReportType 'HTML' -Path "$Path\$domain\GroupPolicy\Reports\$GPOName.html"
    }

    # Count GPOs files for reporting
    $gpos = (Get-ChildItem -Path "$Path\$domain\GroupPolicy\Reports" -Filter *.html).Count

    Write-Verbose -Message "[$(Get-Date -Format G)]  $gpos Active Directory Group Policy Objects Exported`r`n`r`n" -Verbose
    Write-Output "$gpos Active Directory Group Policy Objects Exported $(Get-Date -Format G)`r`n" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    $gpos = $null
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
    $gpos = $null
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
    $ouCount = $null
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
    while ($reader.ReadLine() -ne $null) { $rows++ }
    $reader.Close()
    $rows--
    if ($rows -lt 0) {
        $rows = 0
    }

    Write-Verbose -Message "[$(Get-Date -Format G)]  $rows Active Directory Confidential Bit Details Exported`r`n`r`n" -Verbose
    Write-Output "$rows Active Directory Confidential Bit Details Exported $(Get-Date -Format G)`r`n" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    $rows = $null
    #endregion Export AD Confidentiality Bit

    #region Export AD Default Domain Password Policy
    Write-Verbose -Message "[$(Get-Date -Format G)]  Exporting Active Directory Default Domain Password Policy" -Verbose
    Write-Output "Exporting Active Directory Default Domain Password Policy $(Get-Date -Format G)" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    Get-ADDefaultDomainPasswordPolicy | Select-Object -Property PasswordHistoryCount, MaxPasswordAge, MinPasswordAge,
        MinPasswordLength, ComplexityEnabled, ReversibleEncryptionEnabled, LockoutDuration, LockoutThreshold,
        LockoutObservationWindow, DistinguishedName |
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
        Select-Object 'DistinguishedName','Name',
            @{Name='msDS-PSOAppliesTo';Expression={(($_.appliesTo -split (",") | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},
            'PasswordHistoryCount','MaxPasswordAge','MinPasswordAge','MinPasswordLength','ComplexityEnabled',
            'ReversibleEncryptionEnabled','LockoutDuration','LockoutThreshold','LockoutObservationWindow',
            'Precedence' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', '' } |
        Out-File -FilePath "$Path\$domain\$domain-fgppDetails.csv" -Append

    # Count Rows for reporting
    $rows = 0
    $reader = New-Object IO.StreamReader "$Path\$domain\$domain-fgppDetails.csv"
    while ($reader.ReadLine() -ne $null) { $rows++ }
    $reader.Close()
    $rows--
    if ($rows -lt 0) {
        $rows = 0
    }

    Write-Verbose -Message "[$(Get-Date -Format G)]  $rows Active Directory Fine Grained Password Policies Exported`r`n`r`n" -Verbose
    Write-Output "$rows Active Directory Fine Grained Password Policies Exported $(Get-Date -Format G)`r`n" |
        Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
    $rows = $null
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
        while ($reader.ReadLine() -ne $null) { $rows++ }
        $reader.Close()
        $rows--
        if ($rows -lt 0) {
            $rows = 0
        }
        Write-Verbose -Message "[$(Get-Date -Format G)]  $rows Active Directory Domain Trusts Exported`r`n`r`n" -Verbose
        Write-Output "$rows Active Directory Domain Trusts Exported $(Get-Date -Format G)`r`n" |
            Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append -Encoding utf8
        $rows = $null
    }
    else {
        Write-Warning -Message "[$(Get-Date -Format G)]  Get-ADTrust cmdlet Not Available"
        Write-Output "WARNING: Get-ADTrust Not Available $(Get-Date -Format G)" |
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
}
