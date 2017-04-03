
-- #############################################################################
-- Sample SQL Queries for IT Audit Testwork
-- #############################################################################
-- =============================================================================


-- Purpose: Provide sample queries for Auditors to use

-- Revisions:
--    1.0 - Initial Release
--    1.1 - Added Tip regarding NULL Values
--    1.2 - Fixed table aliasing typos
--        - Changed references of '' to IS NOT NULL
--    1.3 - PH - 1/8/16 - Added Base Query to be used when querying AD
--        - Added "Account Operators" to the Admin Query
--		  - Added Placeholder for expressions developed in-house at end of file
--    1.4 - PH - 3/16/16 - Initial Draft of Sample Query Complete.
--    1.41 - PH - 3/18/16 - Fixed bug with Query 3 and 7, Thanks Bill
--    1.5 - PH - 4/6/16 - Updates to query formatting and added additional 
--          criteria to some of the queries.  Also updated ADtestwork Template
--          to match the changes to queries.
--    1.51 - PH - 6/3/16 - Found bug that wouldn't catch all instances of
--           Administrators in query 2 and 3.  Added 2 lines of code to fix.
--    1.52 - PH - 6/15/16 - Found query for UserAccountControl was pulling
--           "Password not Required" which we generally don't care about.  
--           However this can be an issue, so added to query to explicitly
--           check for both conditions.
--    1.53 - PH - 6/20/16 - Added "t1.[msDS-ResultantPSO]" to beginning of
--           certain select statement for Password queries to ensure that 
--           this is looked at.
--           PH - Consolidated Query 9 and 10 together as the theme of 
--           testwork is the same.  Deleted Query 10.
--    1.54 - PH - 6/30/16 - Dianne found a bug in query 4 that would not include
--           accounts that were never logged into before.  Updated query to
--           include accounts that meet that criteria.
--    1.55 - PH - 7/8/16 - Updated queries to not include accounts that are
--           expired, since this is the same as an account being disabled.
--    1.56 - PH - 8/10/16 - Fixed bug in query 6 that showed all [pwdLastSet]
--           set to Null.
--    1.57 - PH - 11/23/16 - Added line to termination query (query 4) to 
--                          account for term list being older than AD script. 
--    1.58 - PH - 11/14/16 - Add query to filter on accountExpires.  Not Null 
--                          and less than date of query being run.
--    1.6 -
--
--           	 To-Do - ***Add calculation to verify Password Expiration 
--                          setting when query is run to appropriate queries
--                          (query 10 has logic)
--               To-Do - ***Add check for Krbtgt check for Password expiration
--               To-Do - ***Add info for Delegated Access***
--               To-Do - ***Add note about recursive admin inheritence
--               
--               
--               To-Do  - ***Look into the Left Join and having Null values 
--                          being present in the results.  DES database is the 
--                          best database to check for this.
--
--				 To-Do - Add language for dual AD accounts




--
-- ### For any query that is modified or created.  Make sure you also add 
-- ### IS NULL to the field that you are filtering on (Unless you don't care
-- ### about the null value in terms of meaning)
-- ### otherwise SQL will omit the results for any record has a null in that 
-- ### column.
--
-- #############################################################################
-- #####      Below are fields that could have NULL in the field.          #####
-- #############################################################################
--
--  GENERALLY USED IN QUERIES
--  accountExpires
--  lockoutTime
--  msDS-UserPasswordExpiryTimeComputed
--  DaysSincePasswordLastSet
--  DaysSinceLastLogin
--  lastLogonTimestamp
--  memberOf
--  pwdLastSet
--

--  GENERALLY NOT USED IN QUERIES
--  msDS-ResultantPSO
--  description
--  givenName
--  badPwdCount
--  adminCount
--  logonCount
--  displayName
--  sn
--  employeeNumber
--  employeeID
--  department


-- =============================================================================
-- =============================================================================
--
-- Notes - If you run a query and it does not seem to be working correctly
-- be sure to check that column attributes are the same among comparisons.
-- Ex: Getting a Date from a VarChar field.
--


--##############################################################################
-- Some queries to run in Powershell or Command line to quickly find policies 
-- with password requirements set inside of them.
--
-- find "Password must meet complexity requirements" *.html 
-- find "Complexity" *.html
-- find "Minimum password length" *.html
-- find "Minimum password age" *.html
-- find "Maximum password age" *.html
-- 
--
--
--
-- The following Group Policy settings are used to find if the Agency has 
-- Lock Idle Session (i.e. Automatic lock of computer screen) in use".
--
--      Windows Server 2008 - Windows Server 2012 must have the following
--      polices in place to work correctly.
--
--          "Enable screen saver"
--          "Password protect the screen saver"
--
--      Windows Server 2012 R2 - and newer must have the following polices
--      in place to work correctly.
-- 
--          "Interactive logon: Machine inactivity limit"
--
--##############################################################################


-- #############################################################################
-- Base Query for running AD testwork
-- #############################################################################

-- This SELECT Statement should be used when performing testwork on AD.  You 
-- should still review the AD download in its entirety to determine if there 
-- is any additional fields that would be useful for testwork or further 
-- investigation.

SELECT  t1.[msDS-ResultantPSO],
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]	   
FROM [Test] AS t1
ORDER BY t1.[relativeIdentifier] ASC



--##############################################################################
--
-- FYI - Before testwork is started, you should perform the following query
-- to ensure you have good data.
--
-- 2nd FYI - As data received by agencies may vary, you may have to customize
-- the query below to work with the data that you received.
--
--
--
-- #############################################################################
-- Query 1
-- AD Testwork - "Current to Term Employee" - Ensure that an employee is not
-- both an active employee and terminated. 
--
-- Run this to ensure there are no terminated employees on the current 
-- employee list.  If there are matches, determine if the account is current or
-- not and remove the false record.
--
-- Make sure to change the date to the date the Terminated Report was run.
--
-- #############################################################################

SELECT 
        t1.[Name],					
        t1.[Hire Date], t1.[EndDate]
        FROM [Test] AS t1 					
WHERE 
EXISTS ( 					
        SELECT * 					
        FROM [Test] AS t2 					
        WHERE
            --The next 3 lines are used in accordance to the data receieved
            --by the agency
            CONVERT(DATETIME,(t2.[TERMINATION DATE])) < '01/01/3000' AND
            CONVERT(DATETIME,(t2.[TERMINATION DATE])) > t1.[Hire Date] AND
            CONVERT(DATETIME,(t2.[TERMINATION DATE])) > t1.[EndDate] AND
            CHARINDEX(t1.[Name], t2.[Name]) > 0) AND
                (
                t1.[Employee Status] LIKE '%Active%' OR  --Optional                					
                t1.[Employee Status] LIKE '%Leave%'      --Optional
                )
        )   	


-- If any employees are found to have matched in both data sets, create a copy 
-- of the data set that needs to be modified and label it xxx_CleanedData.  
-- Afterwhich remove the employee information from that data set so further 
-- queries are not effected by the bad data.  Then drop the orginal database 
-- from the table and import the xxx_CleanedData into the Database.
        


--##############################################################################
-- Query 2
-- AD Testwork - "Admin Like Accounts" - Reviewing "memberof" to determine if 
-- other groups have been granted administrator privileges.
-- 
-- Note that you have to determine if the results are an issue or not
--
-- Note 2: If there are results that doesn't mean they are associated with an
-- account in AD.  You will have to verify if these accounts are associated to
-- another account either by "sAMAccountName" or by the "PrimaryGroupID" (the 
-- last group of numbers to the right of the last "-" in the "objectSid" column)
--
--##############################################################################


SELECT  
        t1.[DN], t1.[cn],t1.[description], t1.[name], t1.[objectSid],
        t1.[RelativeIdentifier], t1.[sAMAccountName], t1.[memberOf],
        t1.[displayName]
FROM [Test] AS t1
WHERE   t1.[memberOf] LIKE '%, Administrators%' OR
        t1.[memberOf] LIKE 'Administrators, %' OR
        t1.[memberOf] LIKE 'Administrators' OR
        t1.[memberOf] LIKE '%Domain Admins%' OR 
        t1.[memberOf] LIKE '%Enterprise Admins%' OR
        t1.[memberOf] LIKE '%Schema Admins%' OR
        t1.[memberOf] LIKE '%Server Operators%' OR
        t1.[memberOf] LIKE '%Backup Operators%' OR
        t1.[memberOf] LIKE '%Account Operators%'




-- #############################################################################
-- Query 3
-- AD Testwork - "Admin Review" - Determines which accounts have admin
-- privileges.     
--
-- Check the Groups.csv file to verify recursive group membership
-- Add group list to query below
-- Also add each groups last section from objectSID for queries against 
-- primaryGroupID
--
-- 
-- Note - The Account Operators, Backup Operators, and Server Operators 
-- account are not inherently bad, but how it is applied can be bad. If you find
-- these accounts get an understanding of how it is used and who is using it.
--
-- 2nd Note - Make sure to include any groups from "Query 4" in the query below
-- so that we will know the individual accounts that have been granted 
-- adminCount rights.
--
-- #############################################################################


SELECT 
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]
FROM [Test] AS t1
WHERE (t1.[userAccountControl] LIKE 'Enabled%' AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '01/01/2000'))
AND (
        t1.[memberOf] LIKE '%, Administrators%' OR
        t1.[memberOf] LIKE 'Administrators, %' OR
        t1.[memberOf] LIKE 'Administrators' OR
        t1.[primaryGroupID] LIKE '544' OR
        t1.[memberOf] LIKE '%Domain Admins%' OR
        t1.[primaryGroupID] LIKE '512' OR
        t1.[memberOf] LIKE '%Enterprise Admins%' OR
        t1.[primaryGroupID] LIKE '519' OR
        t1.[memberof] LIKE '%Schema Admins%' OR
        t1.[primaryGroupID] LIKE '518' OR
        t1.[memberof] LIKE '%Server Operators%' OR
        t1.[primaryGroupID] LIKE '549' OR
        t1.[memberof] LIKE '%Backup Operators%' OR
        t1.[primaryGroupID] LIKE '551' OR
        t1.[memberof] LIKE '%Account Operators%' OR
        t1.[primaryGroupID] LIKE '548'
    )
ORDER BY t1.[relativeIdentifier] ASC




-- #############################################################################
-- Query 4  
-- AD Testwork - "UserAccountControl" - Check for Enabled accounts that have 
-- passwords that don't expire or accounts that do not have passwords set.
--
-- #############################################################################

SELECT  t1.[msDS-ResultantPSO], 
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        CAST(CONVERT(DATETIME, '01/01/3000') - t1.[pwdLastSet] AS INT)
        AS DaysSincePasswordLastSet,
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]
FROM [Test] AS t1
WHERE (t1.[userAccountControl] LIKE 'Enabled%' AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '01/01/2000'))
AND
((t1.[userAccountControl] LIKE 'Enabled%' AND t1.[userAccountControl] 
        LIKE '%Password Does Not Expire%')
OR
(t1.[userAccountControl] LIKE 'Enabled%' AND t1.[userAccountControl] 
        LIKE '%Password Not Required%' AND t1.[pwdLastSet] IS NULL))
		--msDS-User-Account-Control-Computed not 'Password Expired'
ORDER BY t1.[relativeIdentifier] ASC



-- If you are wanting to separate out Admins and non-Admin accounts perform
-- the following queries may be used.

-- #############################################################################
-- #### This was an idea but queries are not complete and only reflect
-- #### Admin users at time. 
-- #############################################################################


-- ADMINS

SELECT  
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]
FROM [Test] AS t1
WHERE t1.[userAccountControl] LIKE 'Enabled - %'
AND
EXISTS
    (
    SELECT *
    FROM [Test] AS t2
    WHERE	
        (
        t1.memberOf LIKE '%, Administrators%' OR
        t1.primaryGroupID LIKE '544' OR
        t1.memberOf LIKE '%Domain Admins%' OR
        t1.primaryGroupID LIKE '512' OR
        t1.memberOf LIKE '%Enterprise Admins%' OR
        t1.primaryGroupID LIKE '519' OR
        t1.memberof LIKE '%Schema Admins%' OR
        t1.primaryGroupID LIKE '518' OR
        t1.memberof LIKE '%Server Operators%' OR
        t1.primaryGroupID LIKE '549' OR
        t1.memberof LIKE '%Backup Operators%' OR
        t1.primaryGroupID LIKE '551' OR
        t1.memberof LIKE '%Account Operators%' OR
        t1.primaryGroupID LIKE '548'
        )
    )
ORDER BY t1.[relativeIdentifier] ASC

-- NON-ADMINS

SELECT  
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]
FROM [Test] AS t1
WHERE t1.[userAccountControl] LIKE 'Enabled - %'
AND
NOT EXISTS
    (
    SELECT *
    FROM [Test] AS t2
    WHERE	
        (
        t1.memberOf LIKE '%, Administrators%' OR
        t1.primaryGroupID LIKE '544' OR
        t1.memberOf LIKE '%Domain Admins%' OR
        t1.primaryGroupID LIKE '512' OR
        t1.memberOf LIKE '%Enterprise Admins%' OR
        t1.primaryGroupID LIKE '519' OR
        t1.memberof LIKE '%Schema Admins%' OR
        t1.primaryGroupID LIKE '518' OR
        t1.memberof LIKE '%Server Operators%' OR
        t1.primaryGroupID LIKE '549' OR
        t1.memberof LIKE '%Backup Operators%' OR
        t1.primaryGroupID LIKE '551' OR
        t1.memberof LIKE '%Account Operators%' OR
        t1.primaryGroupID LIKE '548'
        )
		
    )
ORDER BY t1.[relativeIdentifier] ASC




-- #############################################################################
-- Query 5
-- AD Testwork - "Stale Accounts"  Check for Accounts that have not signed into
-- AD for awhile.
--
-- Note: You must change the 'Manually' entered date to the date that you
-- ran the script against the Entity's Domain Controller.
--
-- Note: Determine what the Entity's criteria for "Stale" or Inactive accounts 
-- and input that amount (+14 Days) in the 'Manually' entered time in the  
-- "Where" statement. For example if they say 90 days is acceptable, you would
-- enter 104.  This is to compensate for the 2 week lag that could be present
-- between Domain Controllers.
-- #############################################################################

SELECT 
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        t1.[lastLogonTimestamp], 
        CAST(CONVERT(DATETIME, '01/01/3000') - t1.[lastLogonTimestamp] AS INT) 
        AS DaysSinceLastLogin,
        t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]
FROM [Test] AS t1
WHERE (t1.[userAccountControl] LIKE 'Enabled%' AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '01/01/2000')) 
AND
(CAST(CONVERT(DATETIME, '01/01/3000') - t1.[lastLogonTimestamp] AS INT) > '104'       
OR t1.[lastLogonTimestamp] IS NULL)
ORDER BY t1.[relativeIdentifier] ASC



-- #############################################################################
-- Query 6
-- AD Testwork - "Password Expiration" - Check for Old Passwords
--
-- Note: You must change the 'Manually' entered date to the date that you
-- ran the script against the Entity's Domain Controller.
--
-- Note: Also change the amount of days that the agency has designated when
-- passwords expire.
--
-- #############################################################################


SELECT  t1.[msDS-ResultantPSO], 
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        CAST(CONVERT(DATETIME, '01/01/3000') - t1.[pwdLastSet] AS INT)
        AS DaysSincePasswordLastSet,
		CAST(CONVERT(DATETIME,t1.[msDS-UserPasswordExpiryTimeComputed]) 
        - t1.[pwdLastSet] AS INT) AS PasswordExpirationSetting,
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]
FROM [Test] AS t1
WHERE (t1.[userAccountControl] LIKE 'Enabled%' AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '01/01/2000'))
AND
     t1.[msDS-User-Account-Control-Computed] NOT LIKE '%Password Expired%' 
AND
     (CAST(CONVERT(DATETIME, '01/01/3000') - t1.[pwdLastSet] AS INT) > '104' 
     OR (t1.[pwdLastSet] IS NULL))
ORDER BY t1.[relativeIdentifier] ASC                                           



--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
----------------                                                   -------------
----------------   This may be the replacement query for the       -------------
----------------   above Password Expiration Query.                -------------
----------------                                                   -------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

/****** Script for SelectTopNRows command from SSMS  ******/
SELECT  t1.[msDS-ResultantPSO], 
        CAST(CONVERT(DATETIME,t1.[msDS-UserPasswordExpiryTimeComputed]) 
        - t1.[pwdLastSet] AS INT)
        AS PasswordExpirationSetting,
		t1.[userAccountControl], 
		t1.[accountExpires],
		t1.[pwdLastSet],
		CAST(CONVERT(DATETIME, '01/01/3000') - t1.[pwdLastSet] AS INT)
        AS DaysSincePasswordLastSet,
		t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name],
        t1.[relativeIdentifier],
        t1.[department], t1.[employeeNumber], t1.[employeeID]
FROM [Test] AS t1
WHERE (t1.[userAccountControl] LIKE 'Enabled%' AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '01/01/2000'))
AND
     t1.[msDS-User-Account-Control-Computed] NOT LIKE '%Password Expired%' 
AND
     (CAST(CONVERT(DATETIME, '01/01/3000') - t1.[pwdLastSet] AS INT) > '104' 
     OR (t1.[pwdLastSet] IS NULL))
ORDER BY PasswordExpirationSetting, userAccountControl ASC   






--##############################################################################
-- Query 7
-- AD Testwork - "Terminated AD Accounts" - Looking for AD accounts that are 
-- associated with an employee on the Terminated User List. 
-- 
--
-- #############################################################################


--******************************************************************************
--******************************************************************************
--**********                                                          **********
--********** Before running this query, you MUST make sure Query #1   **********
--********** has been performed and the correct database is loaded.   **********
--********** Otherwise you may get false positives as a result.       **********
--**********                                                          **********
--******************************************************************************
--******************************************************************************



-- ####################################
-- This is for comparing names (no unique identifier available) with the 
-- following information available.
--
-- Active Directory Name = Broken Apart (First, I, Last)
-- Current Employee Name = Broken Apart (First, I, Last)
-- Terminated Employee Name = Broken Apart (First, I, Last)
--
-- Note: Put the date input as the date the AD query was run. 
--
-- ####################################
--
--  
-- 
SELECT 
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]	
FROM [Test] AS t1
WHERE (t1.[userAccountControl] LIKE 'Enabled%' AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '01/01/2000'))
AND EXISTS (
--Determine if the Agency uses "EmployeeNumber" or "employeeID" between
--Systems.  Otherwise use the name comparison
        SELECT *
        FROM [Test] AS t2
        WHERE ISNULL(CHARINDEX (t1.[sn] , t2.[Last Name]),0) > 0
        AND ISNULL(CHARINDEX (t1.[givenName] , t2.[First Name]),0) > 0
        AND t2.[EFFECTIVE DATE] <= CONVERT(DATETIME, '01/01/3000')
		--This line ensures that term lists generated after AD script
		--is run does not produce false positive results
		AND t2.[EFFECTIVE DATE] <= CONVERT(DATETIME, '01/01/2000')
        )
ORDER BY t1.[sn] ASC



--########################
-- To Verify the names and logic is correct.  You can apply the query in
-- reverse to ensure the results are accurate.
--########################

SELECT *
        FROM [Test] AS t2
        Where
 EXISTS (
        Select *
        FROM [Test] AS t1
        WHERE (t1.[userAccountControl] LIKE 'Enabled%' 
        AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '01/01/2000'))
		AND
        (
        ISNULL(CHARINDEX (t2.[Last Name], t1.[sn]),0) > 0
        AND ISNULL(CHARINDEX (t2.[First Name], t1.[givenName]),0) > 0
        AND t2.[Term Date] <= CONVERT(DATETIME, '01/01/2000'))
        )
ORDER BY t2.[Last Name] ASC




--##############################################################################
--##############################################################################
--##############################################################################
--##############################################################################
--###################           EXPERIMENTAL!!!!!         ######################
--###################    Has not been Vetted currently    ######################
--##############################################################################
--##############################################################################
--##############################################################################

SELECT 
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]	
        t2.[First Name] AS 'Terminated List First Name', 
        t2.[Last Name] AS 'Terminated List Last Name', t2.[Term Date]
FROM [Test] AS t1
INNER JOIN [Test] AS t2
ON t1.[sn] = t2.[Last Name] and t1.[givenName] = t2.[First Name]
WHERE (t1.[userAccountControl] LIKE 'Enabled%' AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '01/01/2000'))

		
		
--AND EXISTS (
     --Determine if the Agency uses "EmployeeNumber" or "employeeID" between
     --Systems.  Otherwise use the name comparison logic
--       SELECT *
--       FROM [Test] AS t2
--       WHERE 
--      (
--      ISNULL(CHARINDEX (t1.[sn] , t2.[Last Name]),0) > 0
--      AND ISNULL(CHARINDEX (t1.[givenName] , t2.[First Name]),0) > 0
--      AND t2.[Term Date] <= CONVERT(DATETIME, '01/01/2000'))
--      )
--ORDER BY t1.[sn] ASC


--##############################################################################
--##############################################################################
--##############################################################################
--##############################################################################
--###################           EXPERIMENTAL!!!!!         ######################
--##############################################################################
--##############################################################################
--##############################################################################
--##############################################################################







--##############################################################################
-- Query 8
-- AD Testwork - "Non-Matched Accounts" - Looking for non-matched accounts - 
-- This is to check for AD accounts that are not associated with current 
-- user list.
-- 
--
-- #############################################################################

--******************************************************************************
--******************************************************************************
--**********                                                          **********
--********** Before running this query, you MUST make sure Query #1   **********
--********** has been performed and the correct database is loaded.   **********
--********** Otherwise you may get false positives as a result.       **********
--**********                                                          **********
--******************************************************************************
--******************************************************************************


-- ####################################
-- This is for comparing names (no unique identifier available) with the 
-- following information available.
--
-- Active Directory Name = Broken Apart (First, I, Last)
-- Current Employee Name = Broken Apart (First, I, Last)
-- Terminated Employee Name = Broken Apart (First, I, Last)
--
-- Note: Put the date input as the date the AD query was run. 
--
-- ####################################
--
--
-- 
SELECT  t1.[msDS-ResultantPSO], 
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]	
FROM [Test] AS t1
WHERE (t1.[userAccountControl] LIKE 'Enabled%' AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '01/01/2000'))
AND NOT EXISTS (
        SELECT *
        FROM [Test] AS t2
        WHERE ISNULL(CHARINDEX (t1.[sn] , t2.[Last Name]),0) > 0
        AND ISNULL(CHARINDEX (t1.[givenName] , t2.[First Name]),0) > 0
        AND t2.[Hire Date] <= CONVERT(DATETIME, '01/01/2000')
        )
AND NOT EXISTS (
        SELECT *
        FROM [Test] AS t3
        WHERE ISNULL(CHARINDEX (t1.[sn] , t3.[Last Name]),0) > 0
        AND ISNULL(CHARINDEX (t1.[givenName] , t3.[First Name]),0) > 0
        AND t3.[EFFECTIVE DATE] <= CONVERT(DATETIME, '01/01/2000')
        )
ORDER BY t1.[sn] ASC



--##############################################################################
-- Query 9    
-- Query for account that can connect to the Internal network from an External
-- Network. 
--
-- Note: This testwork is designed to determine if only authorized users are 
-- allowed to connect to the internal network from the internet.  This can be 
-- through VPN, Direct Access, Remote Desktop, or whatever software that the 
-- agency uses.

-- NOTE: If this software is NOT tied to AD, then additional work will need to
-- be performed outside of AD.
--
--##############################################################################


SELECT 
        t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[department], t1.[employeeNumber], t1.[employeeID]	
FROM [Test] AS t1
WHERE (t1.[userAccountControl] LIKE 'Enabled%' AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '01/01/2000'))
AND (
        t1.[memberOf] LIKE '%VPN%'
        OR EXISTS (
            SELECT *
            FROM [Test] AS t3
            WHERE ISNULL(CHARINDEX (t1.[sAMAccountName] , t3.[User]),0) > 0
        )
    )
AND NOT EXISTS (
        SELECT *
        FROM [Test] AS t2
        WHERE ISNULL(CHARINDEX (t1.[sn] , t2.[Last Name]),0) > 0
        AND ISNULL(CHARINDEX (t1.[givenName] , t2.[First Name]),0) > 0
        AND t2.[Hire Date] <= CONVERT(DATETIME, '01/01/3000')
        AND t2.[EndDate] >= CONVERT(DATETIME, '01/01/2000')
    )
ORDER BY t1.[relativeIdentifier] ASC





--##############################################################################
-- Query 10    
-- Query to see the Password Expiration Policy in affect for accounts 
-- in Active Directory. 
--
--
--##############################################################################


SELECT  t1.[msDS-ResultantPSO], 
        CAST(CONVERT(DATETIME,t1.[msDS-UserPasswordExpiryTimeComputed]) 
        - t1.[pwdLastSet] AS INT)
        AS PasswordExpirationSetting, t1.[userAccountControl], 
        t1.[accountExpires], t1.[pwdLastSet], t1.[DN], t1.[displayName], 
        t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[cn], 
        t1.[sAMAccountName] AS 'Username (sAMAccountName)', t1.[name],
        t1.[relativeIdentifier], 
        t1.[department], t1.[employeeNumber], t1.[employeeID]
FROM [Test] AS t1
WHERE (t1.[userAccountControl] LIKE 'Enabled%')





















--##############################################################################
--##############################################################################
--##############################################################################
--##########                                                          ##########
--##########     Below are Queries that are work in progress or are   ##########
--##########     theoretical.  These have not been verified and put   ##########
--##########     into a standard format.  If you choose to use them   ##########
--##########     make sure you vet the output.                        ##########
--##########                                                          ##########
--##############################################################################
--##############################################################################
--##############################################################################



--##############################################################################
--
-- 
-- AD Testwork - AD to Current User List - This is to check for AD accounts that
-- are not associated with current user list.
-- 
--
-- #############################################################################


-- ####################################
-- 
-- This is for comparing names (no unique identifier available) with 
-- the following information available.
--
-- Active Directory Name = Broken Apart (First, I, Last)
-- Current Employee Name = Broken Apart (First, I, Last)
--
-- Note: Put in the date input the date the AD query was run. 
--
-- ####################################
-- 

SELECT 
       t1.[DN], t1.[objectClass], t1.[cn], t1.[description], t1.[givenName], 
       t1.[initials], t1.[sn], t1.[whenCreated], t1.[whenChanged],  
       t1.[displayName], t1.[memberOf],t1.[name], t1.[userAccountControl], 
       t1.[badPwdCount], t1.[pwdLastSet],t1.[primaryGroupID], t1.[objectSid], 
       t1.[relativeIdentifier], t1.[adminCount], t1.[accountExpires], 
       t1.[logonCount], t1.[sAMAccountName], t1.[sAMAccountType],  
       t1.[lockoutTime],t1.[objectCategory], t1.[lastLogonTimestamp], 
       t1.[msDS-User-Account-Control-Computed], 
       t1.[msDS-UserPasswordExpiryTimeComputed]
FROM [Test] AS t1
WHERE                                                           
t1.[userAccountControl] LIKE 'Enabled%' 
AND EXISTS (
        SELECT *
        FROM [Test] AS t2
		WHERE ISNULL(CHARINDEX (t1.[sn] , t2.[Last Name]),0) > 0
		AND ISNULL(CHARINDEX (t1.[givenName] , t2.[First Name]),0) > 0
       	AND t2.[Hire Date] <= CONVERT(DATETIME, '04/14/2015') --Optional
        )
ORDER BY t1.[sn] ASC


-- ####################################
--
-- 
-- This is for comparing names (no unique identifier available) with the 
-- following information available.
--
-- Active Directory Name = Broken Apart (First, I, Last)
-- Current Employee Name = Together (Last, First)
--
-- Note: Put the date input as the date the AD 
--
-- #############################################
-- 

-- Need to modify for the above criteria, remove this line when complete
SELECT 
       t1.[DN], t1.[objectClass], t1.[cn], t1.[description], t1.[givenName], 
       t1.[initials], t1.[sn], t1.[whenCreated], t1.[whenChanged],  
       t1.[displayName], t1.[memberOf],t1.[name], t1.[userAccountControl], 
       t1.[badPwdCount], t1.[pwdLastSet],t1.[primaryGroupID], t1.[objectSid], 
       t1.[relativeIdentifier], t1.[adminCount], t1.[accountExpires], 
       t1.[logonCount], t1.[sAMAccountName], t1.[sAMAccountType],  
       t1.[lockoutTime],t1.[objectCategory], t1.[lastLogonTimestamp], 
       t1.[msDS-User-Account-Control-Computed], 
       t1.[msDS-UserPasswordExpiryTimeComputed]
FROM [Test] AS t1
WHERE                                                           
t1.[userAccountControl] LIKE 'Enabled%' 
AND EXISTS (
        SELECT *
        FROM [Test] AS t2
		WHERE ISNULL(CHARINDEX (t1.[sn] , t2.[Name]),0) > 0
		AND ISNULL(CHARINDEX (t1.[givenName] , t2.[Name]),0) > 0
       	AND t2.[Hire Date] <= CONVERT(DATETIME, '04/14/2015') --Optional
        )
ORDER BY t1.[sn] ASC


--##############################################################################
--
-- 
-- AD Testwork - AD to Terminated User List - This is to check for AD accounts 
-- that are not associated with current user list.
-- 
--
-- #############################################################################




-- #############################################################################
--
-- 
-- This is for comparing names (no unique identifier available) with the 
-- following information available.
--
-- Active Directory Name = Broken Apart (First, I, Last)
-- Terminated User Name = Broken Apart (First, I, Last)
--
-- Note: Put the date input as the date the AD 
--
-- #############################################################################
-- 

SELECT 
       t1.[DN], t1.[objectClass], t1.[cn], t1.[description], t1.[givenName], 
       t1.[initials], t1.[sn], t1.[whenCreated], t1.[whenChanged],  
       t1.[displayName], t1.[memberOf],t1.[name], t1.[userAccountControl], 
       t1.[badPwdCount], t1.[pwdLastSet],t1.[primaryGroupID], t1.[objectSid], 
       t1.[relativeIdentifier], t1.[adminCount], t1.[accountExpires], 
       t1.[logonCount], t1.[sAMAccountName], t1.[sAMAccountType],  
       t1.[lockoutTime],t1.[objectCategory], t1.[lastLogonTimestamp], 
       t1.[msDS-User-Account-Control-Computed], 
       t1.[msDS-UserPasswordExpiryTimeComputed]
FROM [Test] AS t1
WHERE t1.[sn] IS NOT NULL                                                           
AND t1.[userAccountControl] LIKE '%Enabled%' 
AND EXISTS (
        SELECT *
        FROM [Test] AS t3
        WHERE ISNULL(CHARINDEX (t1.[sn] , t2.[Last Name]),0) > 0
		AND ISNULL(CHARINDEX (t1.[givenName] , t2.[First Name]),0) > 0
		AND t3.[EFFECTIVE DATE] <= CONVERT(DATETIME, '04/14/2015'))
        )
ORDER BY t1.[sn] ASC



-- #############################################################################
--
-- 
-- This is for comparing names (no unique identifier available) with the 
-- following information available.
--
-- Active Directory Name = Broken Apart (First, I, Last)
-- Terminated User Name = Together (Last, First)
--
-- Note: Put the date input as the date the AD 
--
-- #############################################################################
-- 

-- Need to modify for the above criteria, remove this line when complete
SELECT 
       t1.[DN], t1.[objectClass], t1.[cn], t1.[description], t1.[givenName], 
       t1.[initials], t1.[sn], t1.[whenCreated], t1.[whenChanged],  
       t1.[displayName], t1.[memberOf],t1.[name], t1.[userAccountControl], 
       t1.[badPwdCount], t1.[pwdLastSet],t1.[primaryGroupID], t1.[objectSid], 
       t1.[relativeIdentifier], t1.[adminCount], t1.[accountExpires], 
       t1.[logonCount], t1.[sAMAccountName], t1.[sAMAccountType],  
       t1.[lockoutTime],t1.[objectCategory], t1.[lastLogonTimestamp], 
       t1.[msDS-User-Account-Control-Computed], 
       t1.[msDS-UserPasswordExpiryTimeComputed]
FROM [Test] AS t1
WHERE t1.[sn] IS NOT NULL 
AND t1.[userAccountControl] LIKE 'Enabled%' 
AND
EXISTS (
        SELECT *
        FROM [Test] AS t2
        WHERE ISNULL(CHARINDEX (t1.[sn] , t2.[Last Name]),0) > 0
		AND ISNULL(CHARINDEX (t1.[givenName] , t2.[First Name]),0) > 0
		)


-- #############################################################################
-- Dealing with NULL Values
-- #############################################################################

--When you are querying field to EXCLUDE certain data (say you don't want to
--see anything in the Description field that includes the word 'Puppies'),
--you need to explicitly include NULL values in your query.
SELECT *
FROM [Test]
WHERE [description] NOT LIKE '%Puppies%' OR [description] IS NULL




-- #############################################################################
-- Terminated Check -> AD
-- #############################################################################
-- This is for comparing names (no unique identifier available)
SELECT 
		t1.[DN], t1.[cn], t1.[givenName], t1.[sn], t1.[displayName], t1.[name], 
        t1.[sAMAccountName], t1.[description], t1.[memberOf], 
        t1.[primaryGroupID], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], t1.[accountExpires], 
        t1.[pwdLastSet], t1.[msDS-UserPasswordExpiryTimeComputed], 
        t1.[objectSid], t1.[adminCount], t1.[lockoutTime], 
        t1.[lastLogonTimestamp], t1.[homeDirectory], t1.[homeDrive], 
        t1.[isCriticalSystemObject], t1.[whenCreated], t1.[whenChanged] 
FROM [Test] AS t1
WHERE t1.[sn] IS NOT NULL and t1.[userAccountControl] NOT LIKE '%Disabled%' AND
EXISTS (
        SELECT *
        FROM [Test] AS t2
        WHERE (PATINDEX(t1.sn, t2.[Name - Last]) > 0 
             AND PATINDEX(t1.givenName, t2.[Name - First]) > 0)
)
	


-- #############################################################################
-- Terminated Check 2 -> AD
-- #############################################################################
-- Alternative query for comparing names
SELECT t1.DN, t1.cn, t1.description, t1.memberOf, t1.userAccountControl, 
t1.[msDS-User-Account-Control-Computed], t1.pwdLastSet, t1.accountExpires, 
t1.[msDS-UserPasswordExpiryTimeComputed], t1.lastLogonTimestamp, t1.whenCreated, 
t1.whenChanged, t2.*
FROM [Test] AS t1, [Test] AS t2
WHERE t1.sn IS NOT NULL AND t1.userAccountControl NOT LIKE '%Disabled%' 
AND (PATINDEX(t1.sn, t2.[Name - Last]) > 0 
AND PATINDEX(t1.givenName, t2.[Name - First]) > 0)



-- #############################################################################
-- Terminated Check (Uniqued Identifier) --> AD
-- #############################################################################
-- Use this query if you have a unique identifier between AD and your 
-- Terminated Listing
SELECT t1.DN, t1.cn, t1.description, t1.memberOf, t1.userAccountControl, 
t1.[msDS-User-Account-Control-Computed], t1.pwdLastSet, t1.accountExpires, 
t1.[msDS-UserPasswordExpiryTimeComputed], t1.lastLogonTimestamp, t1.whenCreated, 
t1.whenChanged, t2.*
FROM [Test] AS t1, [Test] AS t2
WHERE t1.sn IS NOT NULL AND t1.userAccountControl NOT LIKE '%Disabled%' 
AND (t1.employeeNumber = t2.EmpID)



-- #############################################################################
-- Non-Current Match -> AD
-- #############################################################################
-- NOTE the extra "Not Likes" to show how to exclude OUs if desired
SELECT t1.DN, t1.cn, t1.givenName, t1.sn, t1.description, t1.memberOf, 
t1.userAccountControl, t1.[msDS-User-Account-Control-Computed], t1.pwdLastSet, 
t1.accountExpires, t1.[msDS-UserPasswordExpiryTimeComputed], 
t1.lastLogonTimestamp, t1.whenCreated, t1.whenChanged
FROM [Test] AS t1
WHERE t1.DN NOT LIKE '%OU=Service Accounts%' AND t1.DN 
NOT LIKE '%OU=Generic Accounts%'
AND t1.userAccountControl NOT LIKE '%Disabled%' AND
NOT EXISTS (
        SELECT *
        FROM [Test] AS t2
        WHERE (CHARINDEX(t1.sn, t2.[Name - Last]) > 0 
        AND CHARINDEX(t1.givenName, t2.[Name - First]) > 0)
)



-- #############################################################################
-- Password Last Set Check
-- #############################################################################
-- Adjust table name as needed
-- Adjust date in the WHERE clause to be 14 days before the time frame you wish
SELECT t1.DN, t1.cn, t1.description, t1.memberOf, t1.userAccountControl, 
t1.[msDS-User-Account-Control-Computed], t1.pwdLastSet, t1.accountExpires, 
t1.[msDS-UserPasswordExpiryTimeComputed], t1.lastLogonTimestamp, t1.whenCreated,
t1.whenChanged
FROM [Test] AS t1
WHERE t1.pwdLastSet < '2015-01-01 00:00:00' AND t1.userAccountControl 
NOT LIKE '%Disabled%'







-- #############################################################################
-- Primary Group ID Not 513 (Domain Users)
-- #############################################################################
SELECT t1.DN, t1.CN, t1.description, t1.primaryGroupID, t1.memberOf, 
t1.userAccountControl, t1.[msDS-User-Account-Control-Computed], t1.pwdLastSet, 
t1.accountExpires, t1.[msDS-UserPasswordExpiryTimeComputed], 
t1.lastLogonTimestamp, t1.whenCreated, t1.whenChanged
FROM [Test] AS t1
WHERE t1.primaryGroupID NOT LIKE '513' AND t1.userAccountControl 
NOT LIKE '%Disabled%'



-- #############################################################################
-- VPN Users
-- #############################################################################
SELECT t1.DN, t1.cn, t1.description, t1.memberOf, t1.userAccountControl, 
t1.[msDS-User-Account-Control-Computed], t1.pwdLastSet, t1.accountExpires, 
t1.[msDS-UserPasswordExpiryTimeComputed], t1.lastLogonTimestamp, 
t1.whenCreated, t1.whenChanged
FROM [Test] AS t1
WHERE t1.memberOf LIKE '%VPN%' AND t1.userAccountControl NOT LIKE '%Disabled%'



-- #############################################################################
-- VPN Vendors
-- #############################################################################
SELECT t1.DN, t1.cn, t1.description, t1.memberOf, t1.userAccountControl, 
t1.[msDS-User-Account-Control-Computed], t1.pwdLastSet, t1.accountExpires, 
t1.[msDS-UserPasswordExpiryTimeComputed], t1.lastLogonTimestamp, 
t1.whenCreated, t1.whenChanged
FROM [Test] AS t1
WHERE t1.memberOf LIKE '%VPN%' AND t1.DN LIKE '%OU=Vendors%' 
AND t1.userAccountControl NOT LIKE '%Disabled%'



-- #############################################################################
-- Vendors
-- #############################################################################
SELECT t1.DN, t1.cn, t1.description, t1.memberOf, t1.userAccountControl, 
t1.[msDS-User-Account-Control-Computed], t1.pwdLastSet, t1.accountExpires, 
t1.[msDS-UserPasswordExpiryTimeComputed], t1.lastLogonTimestamp, 
t1.whenCreated, t1.whenChanged
FROM [Test] AS t1
WHERE t1.DN LIKE '%OU=Vendors%' AND t1.userAccountControl 
NOT LIKE '%Disabled%'



-- #############################################################################
-- Not following Account Reconciliation Policy
-- #############################################################################
-- To provide more ideas, this query is to check an entity's Account 
-- Reconciliation Policy against real-life.

-- In this instance, the date range was modified to be 44 days before the time 
-- when the AD scripts were run. This is 30 days + the 14 day grace period for 
-- lastLogonTimestamp

SELECT t1.DN, t1.cn, t1.description, t1.memberOf, t1.userAccountControl, 
t1.[msDS-User-Account-Control-Computed], t1.pwdLastSet, t1.accountExpires, 
t1.[msDS-UserPasswordExpiryTimeComputed], t1.lastLogonTimestamp, t1.whenCreated, 
t1.whenChanged
FROM [Test] AS t1
WHERE t1.lastLogonTimestamp < '2014-09-01 00:00:00'
AND t1.DN NOT LIKE '%OU=Service Accounts%'
AND t1.DN NOT LIKE '%OU=Test Accounts%'
AND t1.DN NOT LIKE '%OU=Special Account%'
AND t1.DN NOT LIKE '%OU=Generic Accounts%'
AND t1.userAccountControl NOT LIKE '%Disabled%'








-- #############################################################################
-- Below are Random ideas for code that may be useful in querying.
--
-- These are NOT normally used in an audit 
--
-- #############################################################################


--******************************************************************************
-- This code is designed to pull out the last chuck of data that is too the
-- right of a delimiter (in this case "-").
-- PH 1/8/16
--
-- right(t1.[objectSid],(len(t1.[objectSid])-(Charindex('-',t1.[objectSid],
-- ((len(t1.[objectSid]))-6))))) as RelativeIdentifier,
--
-- Example of use
--
-- 1) Orignal Data -> S-1-5-21-12345678-1234567890-123456789-1316
-- 2) Run above query
-- 3) Output = 1316
--******************************************************************************
-- 



--******************************************************************************
-- This code is used to remove preceeding zeros in a field and creates an 
-- alternative column.

-- str_col = name of column that has leading zeros
-- nameofcolumn is a placeholder for the name of new column

-- SUBSTRING(str_col, PATINDEX('%[^0]%', str_col), LEN(str_col)) AS nameofcolumn

--Example
-- SUBSTRING([employeeID], PATINDEX('%[^0]%', [employeeID]), LEN([employeeID])) 
-- as EIN










--******************************************************************************
--
-- This code is used to apply "IF" Statements inside of a select statement if
-- you do not have the ability to create or alter tables.
-- PH 1/25/2016
--
--
--
--SELECT	t1.[DN],
--		t1.[cn],
--		t1.[description],
--		t1.[name],
--		t1.[objectSid],
--		t1.[sAMAccountName],
--		t1.[memberOf],
--		t1.[displayName],
--		CASE 
--			WHEN t1.[memberOf] LIKE '%, Administrators%' THEN 'Check This 1'
--			WHEN t1.[memberOf] LIKE '%Domain Admins%' THEN 'Check This 2'
--			WHEN t1.[memberOf] LIKE '%Enterprise Admins%' THEN 'Check This 3'
--			WHEN t1.[memberOf] LIKE '%Schema Admins%' THEN 'Check This 4'
--			WHEN t1.[memberOf] LIKE '%Server Operators%' THEN 'Check This 5'
--			WHEN t1.[memberOf] LIKE '%Backup Operators%' THEN 'Check This 6'
--			WHEN t1.[memberOf] LIKE '%Account Operators%' THEN 'Check This 7'
--			ELSE 'This Does Not Work' END AS Test
--FROM [Test] AS t1
--ORDER BY Test
--
--******************************************************************************
--
--******************************************************************************
--
-- This code is used to truely find Distinct fields in a SQL table.
--
--
--     SELECT *
--     FROM (
--         SELECT *,
--            ROW_NUMBER() OVER (PARTITION BY [ColumnName] ORDER BY 
--            [ColumnName]) AS ROW_NUMBER
--         FROM [TableName]
--         ) AS ROWS
--     WHERE ROW_NUMBER = 1 
--     ORDER BY [ColumnName] ASC
--
--******************************************************************************



SELECT  col1, ....., col@      -- <<== select as many columns as you want
        INTO [New tableName]
FROM    [Source Table Name]




SELECT t1.USER_ID, t1.EIN, t1.LAST_NAME, t1.FIRST_NAME, 
t1.APPLICATION_ROLE_ID, t1.APPLICATION_ROLE_NAME, t1.INTERNAL_EXTERNAL_FLAG, 
t2.[EIN], t2.[userAccountControl], t3.Term_Date
FROM Test AS t1
INNER JOIN [Test] AS t2
ON t1.[EIN] = t2.[EIN] 
INNER JOIN [Test] AS t3
ON t1.[EIN] = t3.[EIN2]

WHERE EXISTS (
 SELECT *
 FROM Test AS t2
 WHERE t1.EIN = t2.EIN 
 AND t2.[userAccountControl] not like 'disabled'
)
ORDER BY t1.[EIN] ASC	



--Code to separate a FULL Name to separate names, needs to be commented for 
--what it does.
Select  t1.[DN], t1.[displayName], t1.[givenName] AS 'First Name (givenName)', 
        t1.[sn] AS 'Last Name (sn)', t1.[initials], t1.[cn],  
        t1.[sAMAccountName] AS 'Username (sAMAccountName)',
        t1.[name], t1.[memberOf], t1.[primaryGroupID],
        t1.[title], t1.[description], t1.[whenCreated], t1.[pwdLastSet],
        t1.[lastLogonTimestamp], t1.[whenChanged],   
        t1.[accountExpires], t1.[userAccountControl], 
        t1.[msDS-User-Account-Control-Computed], 
        t1.[msDS-UserPasswordExpiryTimeComputed],
        t1.[objectSid], t1.[relativeIdentifier], t1.[lockoutTime],
        t1.[employeeID] 
From Test AS t1
Where (t1.[userAccountControl] LIKE 'Enabled%' 
        AND (t1.[accountExpires] IS NULL 
        OR CONVERT(DATETIME,t1.[accountExpires]) >= '5/23/16'))
AND EXISTS 
(
 Select *
 From Test as t2
 Where ISNULL(CHARINDEX 


 (
    --Find this instance inside of the next case statement
	CASE
     -- When the last character in the name is '.', then give the name 
     -- minus 3 characters.
	 When SUBSTRING(t2.[Name],LEN(t2.[Name]),1) = '.'
     Then SUBSTRING(t2.[Name],1,LEN(t2.[Name])-3)
     --When the second to last character is a space, then give the 
     --name minus 2 characters.
	 When SUBSTRING(t2.[Name],LEN(t2.[Name])-1,1) = ' '
     Then SUBSTRING(t2.[Name],1,LEN(t2.[Name])-2)
     --This checks if a space occurs after the ', ' and cuts out the  additional 
     --information. Note that the search includes the first space.
	 When CHARINDEX(' ',REVERSE(t2.Name),0) < CHARINDEX(' ,',REVERSE(t2.Name),0)
     Then SUBSTRING(t2.[Name],1,Len(t2.Name)-CHARINDEX(' ',REVERSE(t2.Name)))
     --Default case - all other instances do this
	 ELSE t2.Name
    END, 
	CONCAT(t1.[sn],', ',
    
		CASE
			When CHARINDEX(' ',t1.givenName,0)>0
			Then SUBSTRING(t1.givenName,0,CHARINDEX(' ',t1.givenName))
			ELSE t1.givenName
		END
    ),0),0) = 1 
  
  
  AND 
  --******************************************************************************
  --This is to ensure that the two strings are the same length. We had some issues
  --with false positives with multiple last names where the first name is a common
  --name. This eliminates those false positives.
  (
   Len(CASE
     When SUBSTRING(t2.[Name],LEN(t2.[Name]),1) = '.'
     Then SUBSTRING(t2.[Name],1,LEN(t2.[Name])-3)
     When SUBSTRING(t2.[Name],LEN(t2.[Name])-1,1) = ' '
     Then SUBSTRING(t2.[Name],1,LEN(t2.[Name])-2)
     When CHARINDEX(' ',REVERSE(t2.Name),0) < CHARINDEX(' ,',REVERSE(t2.Name),0)
     Then SUBSTRING(t2.[Name],1,Len(t2.Name)-CHARINDEX(' ',REVERSE(t2.Name)))
     ELSE t2.Name
    END) = Len(CONCAT(t1.[sn],', ',t1.[givenName]))
  )
        AND t2.[Effective Date] <= CONVERT(DATETIME, '5/23/16')
)
Order by t1.sn