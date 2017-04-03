@echo off
CLS

:::::::::::::::::::::::::::::::::::::::::
:: Get Domain Root into Variable
:::::::::::::::::::::::::::::::::::::::::
for /F %%A IN ('dsquery * -startnode domainroot -scope base') DO (
SET domain=%%~A
)

:::::::::::::::::::::::::::::::::::::::::
:: Begin Logging
:::::::::::::::::::::::::::::::::::::::::
echo(
echo -----------------------------------------------------
echo(
echo Beginning Execution
md "%domain%" >NUL 2>&1
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Batch File Execution Started at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------
echo(

:::::::::::::::::::::::::::::::::::::::::
:: Active Directory Users (csvde)
:::::::::::::::::::::::::::::::::::::::::
echo Pulling Active Directory Users
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Users Extraction >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Started at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo ----------------------------------------------------- >> "%CD%\%domain%\consoleOutput.txt"

csvde -r "(sAMAccountType=805306368)" -l msDS-ResultantPSO,msDS-User-Account-Control-Computed,msDS-UserPasswordExpiryTimeComputed,* -f "%CD%\%domain%\%domain%-Users.csv" >> "%CD%\%domain%\consoleOutput.txt"

echo Active Directory Users Exported
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Finished at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------
echo(

:::::::::::::::::::::::::::::::::::::::::
:: Active Directory Groups (csvde)
:::::::::::::::::::::::::::::::::::::::::
echo Pulling Active Directory Groups
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Groups Extraction >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Started at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo ----------------------------------------------------- >> "%CD%\%domain%\consoleOutput.txt"

csvde -r "(objectCategory=group)" -f "%CD%\%domain%\%domain%-Groups.csv" -l "distinguishName,sAMAccountName,CN,displayName,name,description,groupType,memberOf,objectSID,msDS-PSOApplied,whenCreated,whenChanged" >> "%CD%\%domain%\consoleOutput.txt"

echo Active Directory Groups Exported
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Finished at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------
echo(

:::::::::::::::::::::::::::::::::::::::::
:: Active Directory OUs (csvde)
:::::::::::::::::::::::::::::::::::::::::
echo Pulling Active Directory Organizational Units
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Organizational Units Extraction >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Started at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo ----------------------------------------------------- >> "%CD%\%domain%\consoleOutput.txt"

csvde -r "(objectCategory=organizationalUnit)" -f "%CD%\%domain%\%domain%-OUs.csv" -l "distinguishName,name,cn,displayName,description" >> "%CD%\%domain%\consoleOutput.txt"

echo Active Directory Organizational Units Exported
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Finished at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------
echo(

:::::::::::::::::::::::::::::::::::::::::
:: Active Directory Computers (csvde)
:::::::::::::::::::::::::::::::::::::::::
echo Pulling Active Directory Computers
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Computers Extraction >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Started at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo ----------------------------------------------------- >> "%CD%\%domain%\consoleOutput.txt"

csvde -r "(objectClass=computer)" -f "%CD%\%domain%\%domain%-Computers.csv" >> "%CD%\%domain%\consoleOutput.txt"

echo Active Directory Computers Exported
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Finished at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------
echo(


:::::::::::::::::::::::::::::::::::::::::
:: Active Directory Group Policy Objects (Microsoft VBScript)
:::::::::::::::::::::::::::::::::::::::::
echo Pulling Group Policy Objects
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Group Policy Objects Extraction >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Started at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo ----------------------------------------------------- >> "%CD%\%domain%\consoleOutput.txt"

md "%domain%\GroupPolicy\gpo" >NUL 2>&1
cscript "%CD%\supplemental\GetReportsForAllGPOs.wsf" "%CD%\%domain%\GroupPolicy\gpo" >> "%CD%\%domain%\consoleOutput.txt"

echo Group Policy Objects Exported
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Finished at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------
echo(


:::::::::::::::::::::::::::::::::::::::::
:: Active Directory GPO Inheritance (dsquery and Microsoft VBScript)
:::::::::::::::::::::::::::::::::::::::::

echo Pulling Group Policy Inheritance
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Group Policy Inheritance Extraction >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Started at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"

md "%domain%\GroupPolicy\inheritance" >NUL 2>&1
cscript "%CD%\supplemental\DumpSOMInfo.wsf" %domain% /showinheritedlinks >> "%CD%\%domain%\GroupPolicy\inheritance\%domain%.txt"
FOR /F delims^=^ eol^= %%i IN ('dsquery ou -limit 0') DO (
cscript "%CD%\supplemental\DumpSOMInfo.wsf" %%i /showinheritedlinks >> "%CD%\%domain%\GroupPolicy\inheritance\%%~i.txt")

echo Group Policy Inheritance Exported
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Finished at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------
echo(

:::::::::::::::::::::::::::::::::::::::::
:: Active Directory OU ACLs (dsacls)
:::::::::::::::::::::::::::::::::::::::::
echo Pulling Organizational Unit Access Control Lists
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Organizational Unit Access Control Lists Export >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Started at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"

md "%domain%\ACL\OU" >NUL 2>&1
FOR /F delims^=^ eol^= %%i IN ('dsquery ou -limit 0') DO (
echo( >> "%CD%\%domain%\ACL\OU\%%~i.txt" && echo ----------%%i---------- >> "%CD%\%domain%\ACL\OU\%%~i.txt" && echo( >> "%CD%\%domain%\ACL\OU\%%~i.txt" && dsacls %%i >> "%CD%\%domain%\ACL\OU\%%~i.txt")

FOR /F delims^=^ eol^= %%j IN ('dsquery * -scope onelevel -filter "(objectCategory=container)"') DO (
echo( >> "%CD%\%domain%\ACL\OU\%%~j.txt" && echo ----------%%j---------- >> "%CD%\%domain%\ACL\OU\%%~j.txt" && echo( >> "%CD%\%domain%\ACL\OU\%%~j.txt" && dsacls %%j >> "%CD%\%domain%\ACL\OU\%%~j.txt")

echo( >> "%CD%\%domain%\ACL\OU\%domain%.txt" && echo ----------"%domain%"---------- >> "%CD%\%domain%\ACL\OU\%domain%.txt" && echo( >> "%CD%\%domain%\ACL\OU\%domain%.txt" && dsacls "%domain%" >> "%CD%\%domain%\ACL\OU\%domain%.txt"

echo Organizational Unit Access Control Lists Exported
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Finished at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------
echo(

:::::::::::::::::::::::::::::::::::::::::
:: Active Directory Confidentiality Bit and Fine-Grained Password Policies (csvde)
:::::::::::::::::::::::::::::::::::::::::
echo Pulling Schema Details
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Schema Details Export >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Started at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"

csvde -d "CN=Schema,CN=Configuration,%domain%" -r (searchFlags:1.2.840.113556.1.4.803:=128) -f "%CD%\%domain%\%domain%-confidentialBit.csv" >> "%CD%\%domain%\consoleOutput.txt"
csvde -d "CN=Password Settings Container,CN=System,%domain%" -f "%CD%\%domain%\%domain%-fgppDetails.csv" >> "%CD%\%domain%\consoleOutput.txt"

echo Schema Details Exported
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Finished at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------
echo(

:::::::::::::::::::::::::::::::::::::::::
:: Active Directory Domain Trusts (csvde)
:::::::::::::::::::::::::::::::::::::::::
echo Pulling Domain Trusts
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Domain Trusts Details Export >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Started at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"

csvde -r "(objectClass=trustedDomain)" -l * -f "%CD%\%domain%\%domain%-trustedDomains.csv" >> "%CD%\%domain%\consoleOutput.txt"

echo Domain Trusts Details Exported
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Execution Finished at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------
echo(

:::::::::::::::::::::::::::::::::::::::::
:: Finish Logging
:::::::::::::::::::::::::::::::::::::::::
echo All commands successfully completed
echo( >> "%CD%\%domain%\consoleOutput.txt"
echo Batch File Execution Finished at %DATE% %TIME% >> "%CD%\%domain%\consoleOutput.txt"
echo(
echo -----------------------------------------------------

:::::::::::::::::::::::::::::::::::::::::
:: Compress Output Data and Clean Up
:::::::::::::::::::::::::::::::::::::::::
echo(
echo -----------------------------------------------------
echo(
echo Compressing Data

"%CD%\supplemental\7za.exe" a -r "%CD%\%domain%.7z" "%CD%\%domain%"
echo(
echo Data compressed
echo(
echo -----------------------------------------------------
echo(
