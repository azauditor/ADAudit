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
        [System.IO.Compression.ZipFile]::CreateFromDirectory($Source,$Path, $compressionLevel, $false)
    }
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
    Specifies the path to output the resultant data. Default is the current working directory.

    .EXAMPLE
    PS> Get-ADAuditData -Verbose

    This example will export AD information to a directory in the current working directory. Verbose output
    enabled to visually monitor the script's progress.

    .EXAMPLE
    PS> Get-ADAuditData -Path 'C:\Users\username\Desktop' -Verbose

    This example will export AD information to the desktop of the user 'username'. Verbose output enabled
    to visually monitor the script's progress.

    .NOTES
    Author: Alex Entringer
    Date: 04/01/2017
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_ -PathType 'Container'})]
        $Path = $(Get-Location)
    )
    #Requires -Version 3.0
    #Requires -Modules ActiveDirectory, GroupPolicy

    $domain = (Get-ADDomain -Current LocalComputer).DistinguishedName

    Write-Verbose -Message "Creating Output Directory $(Get-Date -Format G)"
    if (Test-Path -Path "$Path\$domain") {
        Remove-Item "$Path\$domain" -Recurse -Force -Confirm
    }
    New-Item -Path "$Path\$domain" -ItemType Directory | Out-Null
    Write-Verbose -Message "Output Directory Created $(Get-Date -Format G)"

    Write-Verbose -Message "Starting Execution at $(Get-Date -Format G)"
    Write-Output "Starting Execution at $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt"

    Write-Verbose -Message "Exporting Active Directory Users $(Get-Date -Format G)"
    Write-Output "Exporting Active Directory Users $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append
    Get-ADUser -Filter * -Properties 'accountExpirationDate','adminCount','assistant','canonicalName','cn','comment','company','controlAccessRights','department',
        'departmentNumber','description','displayName','distinguishedName','division','employeeID','employeeNumber','employeeType','generationQualifier','givenName',
        'info','lastLogonTimestamp','mail','managedObjects','manager','memberOf','middleName','msDS-AllowedToDelegateTo','msDS-PSOApplied',
        'msDS-ResultantPSO','msDS-SourceObjectDN','msDS-User-Account-Control-Computed','msDS-UserPasswordExpiryTimeComputed','name','o','objectSid','ou',
        'PasswordLastSet','PasswordExpired','personalTitle','primaryGroupID','sAMAccountName','secretary','seeAlso','servicePrincipalName','sIDHistory',
        'sn','title','uid','uidNumber','userAccountControl','userWorkstations','whenChanged','whenCreated' |
        Select-Object 'accountExpirationDate','adminCount','assistant','canonicalName','cn','comment','company',
            @{Name='controlAccessRights';Expression={$_.controlAccessRights -join ';'}},'department',@{Name='departmentNumber';Expression={$_.departmentNumber -join ';'}},
            'description','displayName','distinguishedName','division','employeeID','employeeNumber','employeeType','generationQualifier','givenName','info','mail',
            @{Name='managedObjects';Expression={(($_.managedObjects -split (",") | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},'manager',
            @{Name='memberOf';Expression={(($_.memberof -split (",") | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},
            'middleName',@{Name='msDS-AllowedToDelegateTo';Expression={$_.'msDS-AllowedToDelegateTo' -join ';'}},
            @{Name="msDS-PSOApplied";Expression={((($_.'msDS-PSOApplied' -join (";"))) -replace ",CN=Password Settings Container,CN=System,$domain" -replace "" ) -replace "CN=" -replace "" }},
            @{Name="msDS-ResultantPSO";Expression={((($_.'msDS-ResultantPSO' -join (";"))) -replace ",CN=Password Settings Container,CN=System,$domain" -replace "" ) -replace "CN=" -replace "" }},
            'msDS-SourceObjectDN',
            @{Name='msDS-User-Account-Control-Computed';Expression={(ConvertFrom-UACComputed($_.'msDS-User-Account-Control-Computed'))}},
            @{Name='msDS-UserPasswordExpiryTimeComputed';Expression={([datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed')).ToString("M/d/yyyy h:mm:ss tt")}},
            @{Name='lastLogonTimestamp';Expression={([datetime]::FromFileTime($_.lastLogonTimestamp)).ToString("M/d/yyyy h:mm:ss tt")}},
            'name',@{Name='o';Expression={$_.o -join ';'}},'objectSid',@{Name='ou';Expression={$_.ou -join ';'}},'PasswordLastSet','PasswordExpired','personalTitle',
            'primaryGroupID','sAMAccountName',@{Name='relativeIdentifer';Expression={($_.SID.Value).Split('-')[-1]}},@{Name='secretary';Expression={$_.secretary -join ';'}},
            @{Name='seeAlso';Expression={$_.seeAlso -join ';'}},@{Name='servicePrincipalName';Expression={$_.servicePrincipalName -join ';'}},
            @{Name='sIDHistory';Expression={$_.sIDHistory -join ';'}},'sn','title',@{Name='uid';Expression={$_.uid -join ';'}},'uidNumber',
            @{Name='userAccountControl';Expression={(ConvertFrom-UAC($_.userAccountControl))}},'userWorkstations','whenChanged','whenCreated' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\$domain-Users.csv" -Append
    Write-Verbose -Message "Active Directory Users Exported $(Get-Date -Format G)"
    Write-Output "Active Directory Users Exported $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append

    Write-Verbose -Message "Exporting Active Directory Groups $(Get-Date -Format G)"
    Write-Output "Exporting Active Directory Groups $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append
    Get-ADGroup -Filter * -Properties 'distinguishedName','sAMAccountName','CN','displayName','name','description','GroupCategory','GroupScope','ManagedBy', 'memberOf','objectSID','msDS-PSOApplied','whenCreated','whenChanged' |
        Select-Object 'distinguishedName','sAMAccountName','CN','displayName','name','description','GroupCategory','GroupScope','ManagedBy',
            @{Name="memberOf";Expression={(($_.memberof -split (",") | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},
            'objectSID',
            @{Name="msDS-PSOApplied";Expression={((($_.'msDS-PSOApplied' -join (";"))) -replace ",CN=Password Settings Container,CN=System,$domain" -replace "" ) -replace "CN=" -replace "" }},
            @{Name='relativeIdentifer';Expression={($_.SID.Value).Split('-')[-1]}},'whenCreated','whenChanged' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\$domain-Groups.csv" -Append
    Write-Verbose -Message "Active Directory Groups Exported $(Get-Date -Format G)"
    Write-Output "Active Directory Groups Exported $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append

    Write-Verbose -Message "Exporting Active Directory Organizational Units $(Get-Date -Format G)"
    Write-Output "Exporting Active Directory Organizational Units $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append
    Get-ADOrganizationalUnit -Filter * -Properties 'DistinguishedName','Name','CanonicalName','DisplayName','Description','whenCreated','whenChanged','ManagedBy' |
        Select-Object 'DistinguishedName','Name','CanonicalName','DisplayName','Description','whenCreated','whenChanged','ManagedBy' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\$domain-OUs.csv" -Append
    Write-Verbose -Message "Active Directory OUs Exported $(Get-Date -Format G)"
    Write-Output "Active Directory OUs Exported $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append

    Write-Verbose -Message "Exporting Active Directory Group Policy Objects $(Get-Date -Format G)"
    Write-Output "Exporting Active Directory Group Policy Objects $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append
    New-Item -Path "$Path\$domain\GroupPolicy" -ItemType Directory | Out-Null
    New-Item -Path "$Path\$domain\GroupPolicy\Reports" -ItemType Directory | Out-Null
    Get-GPO -All @credObject @domainObj | ForEach-Object {
        $GPOName = $_.DisplayName
        Get-GPOReport $_.id -ReportType HTML -Path "$Path\$domain\GroupPolicy\Reports\$GPOName.html"
    }
    Write-Verbose -Message "Active Directory Group Policy Objects Exported $(Get-Date -Format G)"
    Write-Output "Active Directory Group Policy Objects Exported $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append

    Write-Verbose -Message "Exporting Active Directory Group Policy Inheritance $(Get-Date -Format G)"
    Write-Output "Exporting Active Directory Group Policy Inheritance $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append
    New-Item -Path "$Path\$domain\GroupPolicy\Inheritance" -ItemType Directory | Out-Null
    $domainGPI = Get-GPInheritance -Target $domain
    $domainGPI | Select-Object Name,ContainerType,Path,GpoInheritanceBlocked | Format-List | Out-File -FilePath "$Path\$domain\GroupPolicy\Inheritance\$domain.txt"
    $domainGPI | Select-Object -ExpandProperty InheritedGpoLinks | Out-File -FilePath "$Path\$domain\GroupPolicy\Inheritance\$domain.txt" -Append
    Get-ADOrganizationalUnit -Filter * | ForEach-Object {
        $CurrentGPI = Get-GPInheritance -Target $_.DistinguishedName
        $CurrentGPI | Select-Object Name,ContainerType,Path,GpoInheritanceBlocked | Format-List | Out-File -FilePath "$Path\$domain\GroupPolicy\Inheritance\$_.DistinguishedName.txt"
        $CurrentGPI | Select-Object -ExpandProperty InheritedGpoLinks | Out-File -FilePath "$Path\$domain\GroupPolicy\Inheritance\$_.DistinguishedName.txt" -Append
    }
    Write-Verbose -Message "Active Directory Group Policy Inheritance Exported $(Get-Date -Format G)"
    Write-Output "Active Directory Group Policy Inheritance Exported $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append

    Write-Verbose -Message "Exporting Active Directory Organizational Unit Access Control Lists $(Get-Date -Format G)"
    Write-Output "Exporting Active Directory Organizational Unit Access Control Lists $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append
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

    $OUs  = @(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
    $OUs += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
    $OUs += Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -SearchScope OneLevel -LDAPFilter '(objectClass=container)' | Select-Object -ExpandProperty DistinguishedName

    ForEach ($OU in $OUs) {
        Get-Acl -Path "AD:\$OU" | Select-Object -ExpandProperty Access |
            Select-Object @{name='organizationalUnit';expression={$OU}},
                @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}},
                @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}},* |
            ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
            Out-File -FilePath "$Path\$domain\OU\ACLs\$OU.csv" -Append
    }
    Write-Verbose -Message "Active Directory Organizational Unit Access Control Lists Exported $(Get-Date -Format G)"
    Write-Output "Active Directory Organizational Unit Access Control Lists Exported $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append

    Write-Verbose -Message "Exporting Active Directory Confidentiality Bit Details $(Get-Date -Format G)"
    Write-Output "Exporting Active Directory Confidentiality Bit Details $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append
    Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$domain" -LDAPFilter '(searchFlags:1.2.840.113556.1.4.803:=128)' |
        Select-Object 'DistinguishedName','Name' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\$domain-confidentialBit.csv" -Append
    Write-Verbose -Message "Active Directory Confidential Bit Details Exported $(Get-Date -Format G)"
    Write-Output "Active Directory Confidential Bit Details Exported $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append

    Write-Verbose -Message "Exporting Active Directory Fine Grained Password Policies $(Get-Date -Format G)"
    Write-Output "Exporting Active Directory Fine Grained Password Policies $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append

    Get-ADFineGrainedPasswordPolicy -Filter * -Properties 'appliesTo','ComplexityEnabled','DistinguishedName','LockoutDuration','LockoutObservationWindow',
        'LockoutThreshold','MaxPasswordAge','MinPasswordAge','MinPasswordLength','Name','PasswordHistoryCount','Precedence','ReversibleEncryptionEnabled' |
        Select-Object 'DistinguishedName','Name',
            @{Name='msDS-PSOAppliesTo';Expression={(($_.appliesTo -split (",") | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},
            'PasswordHistoryCount','MaxPasswordAge','MinPasswordAge','MinPasswordLength','ComplexityEnabled',
            'ReversibleEncryptionEnabled','LockoutDuration','LockoutThreshold','LockoutObservationWindow','Precedence' |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\$domain-fgppDetails.csv" -Append
    Write-Verbose -Message "Active Directory Fine Grained Password Policies Exported $(Get-Date -Format G)"
    Write-Output "Active Directory Fine Grained Password Policies Exported $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append

    Write-Verbose -Message "Exporting Active Directory Domain Trusts $(Get-Date -Format G)"
    Write-Output "Exporting Active Directory Domain Trusts $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append
    Get-ADTrust -Filter * -Properties * |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$domain\$domain-trustedDomains.csv" -Append
    Write-Verbose -Message "Active Directory Domain Trusts Exported $(Get-Date -Format G)"
    Write-Output "Active Directory Domain Trusts Exported $(Get-Date -Format G)`n`n" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append


    Write-Verbose -Message "Finished Execution at $(Get-Date -Format G)"
    Write-Output "Finished Execution at $(Get-Date -Format G)" | Out-File -FilePath "$Path\$domain\consoleOutput.txt" -Append

    if ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release).Release -ge 394802) {
        Write-Verbose -Message "Compressing Output Data to Zip File $(Get-Date -Format G)"
        New-ZipFile -Path "$Path\$domain.zip" -Source "$Path\$domain"
        Write-Verbose -Message "Output Data Compressed to Zip File $(Get-Date -Format G)"
    }
}
