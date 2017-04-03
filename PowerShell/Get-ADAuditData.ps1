function New-ZipFile {
    # http://stackoverflow.com/questions/1153126/how-to-create-a-zip-archive-with-powershell#13302548
    param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        $Path,
        [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_ -PathType 'Container'})]
        $Source
    )
    Add-Type -Assembly System.IO.Compression.FileSystem
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir,$zipfilename, $compressionLevel, $false)
}

function Get-ADAuditData {
    <#
    .SYNOPSIS
    Queries current AD Domain for data useful for IT Audit Purposes.

    .DESCRIPTION
    This function will extract key information from Active Directory that can be used to analyze The
    management of an AD Domain. It queries information regarding Users, Groups, OUs, Computers,
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

    The Version 4.0 requirement can be dropped to Version 3.0 if the New-ZipFile function is removed.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_ -PathType 'Container'})]
        $Path = $(Get-Location)
    )
    #Requires -Version 4.0
    #Requires -Modules ActiveDirectory
    Import-Module -Name ActiveDirectory

    $domain = (Get-ADDomain -Current LocalComputer).DistinguishedName

    Write-Verbose -Message 'Creating Output Directory'
    New-Item -Path "$Path\$domain" -ItemType Directory | Out-Null
    Write-Verbose -Message 'Output Directory Created'



    # Add User Account Control Lookup table


    # Add msDS-User-Account-Control-Computed Lookup Table




    Write-Verbose -Message 'Exporting Active Directory Users'
    Get-ADUser -Filter * -Properties 'msDS-ResultantPSO','msDS-User-Account-Control-Computed','msDS-UserPasswordExpiryTimeComputed',* |
        Select-Object -ExcludeProperty memberOf,'msDS-UserPasswordExpiryTimeComputed' *,@{Name="memberOf";Expression={(($_.memberof -split (",") |
        Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},@{Name='PasswordExpirationDate';Expression={([datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed')).ToString("M/d/yyyy h:mm:ss tt")}} |
        Export-Csv -Path "$Path\$domain\$domain-Users.csv" -NoTypeInformation -Delimiter '|'
    Write-Verbose -Message 'Active Directory Users Exported'

    Write-Verbose -Message 'Exporting Active Directory Groups'
    Get-ADGroup -Filter * -Properties 'distinguishedName','sAMAccountName','CN','displayName','name','description','groupType','ManagedBy', 'memberOf','objectSID','msDS-PSOApplied','whenCreated','whenChanged' |
        Select-Object 'distinguishedName','sAMAccountName','CN','displayName','name','description','ManagedBy',@{Name="memberOf";Expression={(($_.memberof -split (",") |
        Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},'msDS-PSOApplied','whenCreated','whenChanged' |
        Export-Csv -Path "$Path\$domain\$domain-Groups.csv" -NoTypeInformation -Delimiter '|'
    Write-Verbose -Message 'Active Directory Groups Exported'

    Write-Verbose -Message 'Exporting Active Directory Organizational Units'
    Get-ADOrganizationalUnit -Filter * -Properties 'distinguishedName','name','CanonicalName','DisplayName','description','whenCreated','whenChanged','ManagedBy' |
        Export-Csv -Path "$Path\$domain\$domain-OUs.csv" -NoTypeInformation -Delimiter '|'
    Write-Verbose -Message 'Active Directory OUs Exported'

    Write-Verbose -Message 'Exporting Active Directory Computers'
    Get-ADComputer -Properties * | Export-Csv -Path "$Path\$domain\$domain-Computers.csv" -NoTypeInformation -Delimiter '|'
    Write-Verbose -Message 'Active Directory Computers Exported'

    Write-Verbose -Message 'Exporting Active Directory Group Policy Objects'
    New-Item -Path "$Path\$domain\GroupPolicy" -ItemType Directory | Out-Null
    New-Item -Path "$Path\$domain\GroupPolicy\Reports" -ItemType Directory | Out-Null
    Get-GPO -All @credObject @domainObj | ForEach-Object {
        $GPOName = $_.DisplayName
        Get-GPOReport $_.id -ReportType HTML -Path "$Path\$domain\GroupPolicy\Reports\$GPOName.html"
        Get-GPOReport $_.id -ReportType XML -Path "$Path\$domain\GroupPolicy\Reports\$GPOName.xml"
    }
    Write-Verbose -Message 'Active Directory Group Policy Objects Exported'

    Write-Verbose -Message 'Exporting Active Directory Group Policy Inheritance'
    New-Item -Path "$Path\$domain\GroupPolicy\Inheritance" -ItemType Directory | Out-Null
    Get-GPInheritance -Target $domain | Out-File -FilePath "$Path\$domain\GroupPolicy\Inheritance\$domain.txt"
    Get-ADOrganizationalUnit | ForEach-Object {
        Get-GPInheritance -Target $_.DistinguishedName | Out-File -FilePath "$Path\$domain\GroupPolicy\Inheritance\$_.DistinguishedName.txt"
    }
    Write-Verbose -Message 'Active Directory Group Policy Inheritance Exported'

    Write-Verbose -Message 'Exporting Active Directory Organizational Unit Access Control Lists'
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
            Select-Object @{name='organizationalUnit';expression={$OU}}, `
                   @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, `
                   @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}}, `
                   * | Export-Csv -Path "$Path\$domain\OU\ACLs\$OU" -NoTypeInformation -Delimiter '|'
    }
    Write-Verbose -Message 'Active Directory Organizational Unit Access Control Lists Exported'

    Write-Verbose -Message 'Exporting Active Directory Confidentiality Bit Details'
    Get-ADObject -Partition "CN=Schema,CN=Configuration,$domain" -LDAPFilter '(searchFlags:1.2.840.113556.1.4.803:=128)' |
        Export-Csv -Path "$Path\$domain\$domain-confidentialBit.csv" -NoTypeInformation -Delimiter '|'
    Write-Verbose -Message 'Active Directory Confidential Bit Details Exported'

    Write-Verbose -Message 'Exporting Active Directory Fine Grained Password Policies'
    Get-ADObject -Partition "CN=Password Settings Container,CN=System,$domain" |
        Export-Csv -Path "$Path\$domain\$domain-fgppDetails.csv" -NoTypeInformation -Delimiter '|'
    Write-Verbose -Message 'Active Directory Fine Grained Password Policies Exported'

    Write-Verbose -Message 'Exporting Active Directory Domain Trusts'
    Get-ADTrust -Filter * | Export-Csv -Path "$Path\$domain\$domain-trustedDomains.csv" -NoTypeInformation -Delimiter '|'
    Write-Verbose -Message 'Active Directory Domain Trusts Exported'

    Write-Verbose -Message 'Compressing Output Data to Zip File'
    New-ZipFile -Path "$Path\$domain.zip" -Source "$Path\$domain"
    Write-Verbose -Message 'Output Data Compressed to Zip File'
}
