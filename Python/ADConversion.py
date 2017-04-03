# ADConversion (alias 'ad')
# Title: ADConversion.py
# Purpose: Convert values from csvde output from Active Directory

import os
import sys
import csv
import binascii
from datetime import datetime, timedelta
import fileinput

csv.field_size_limit(1000000000)

options = {'512' : 'Enabled',
           '514' : 'Disabled',
           '528' : 'Enabled - Locked Out',
           '530' : 'Disabled - Locked Out',
           '544' : 'Enabled - Password Not Required',
           '546' : 'Disabled - Password Not Required',
           '560' : 'Enabled - Password Not Required - Locked Out',
           '640' : 'Enabled - Encrypted Text Password Allowed',
           '2048' : 'Enabled - Interdomain Trust Account',
           '2050' : 'Disabled - Interdomain Trust Account',
           '2080' : 'Enabled - Interdomain Trust Account - Password Not Required',
           '2082' : 'Disabled - Interdomain Trust Account - Password Not Required',
           '4128' : 'Enabled - Workstation Trust Account - Password Not Required',
           '4130' : 'Disabled - Workstation Trust Account - Password Not Required',
           '4096' : 'Enabled - Workstation Trust Account',
           '4098' : 'Disabled - Workstation Trust Account',
           '8192' : 'Enabled - Server Trust Account',
           '8194' : 'Disabled - Server Trust Account',
           '66048' : 'Enabled - Password Does Not Expire',
           '66050' : 'Disabled - Password Does Not Expire',
           '66056' : 'Enabled - Password Does Not Expire - HomeDir Required',
           '66064' : 'Enabled - Password Does Not Expire - Locked Out',
           '66066' : 'Disabled - Password Does Not Expire - Locked Out',
           '66080' : 'Enabled - Password Does Not Expire - Password Not Required',
           '66082' : 'Disabled - Password Does Not Expire - Password Not Required',
           '66176' : 'Enabled - Password Does Not Expire - Encrypted Text Password Allowed',
           '69632' : 'Enabled - Workstation Trust Account - Dont Expire Password',
           '131584' : 'Enabled - Majority Node Set (MNS) Account',
           '131586' : 'Disabled - Majority Node Set (MNS) Account',
           '131600' : 'Enabled - Majority Node Set (MNS) Account - Locked Out',
           '197120' : 'Enabled - Majority Note Set (MNS) Account - Password Does Not Expire',
           '532480' : 'Server Trust Account - Trusted For Delegation (Domain Controller)',
           '590336' : 'Enabled - Password Does Not Expire - Trusted For Delegation',
           '590338' : 'Disabled - Password Does Not Expire - Trusted For Delegation',
           '1049088' : 'Enabled - Not Delegated',
           '1049090' : 'Disabled - Not Delegated',
           '2097664' : 'Enabled - Use DES Key Only',
           '2163200' : 'Enabled - Password Does Not Expire - Use DES Key Only',
           '2687488' : 'Enabled - Password Does Not Expire - Trusted For Delegation - Use DES Key Only',
           '4194816' : 'Enabled - PreAuthorization Not Required',
           '4260352' : 'Enabled - Password Does Not Expire - PreAuthorization Not Required',
           '1114624' : 'Enabled - Password Does Not Expire - Not Delegated',
           '1114656' : 'Enabled - Password Not Required - Password Does Not Expire - Not Delegated',
           '3211776' : 'Enabled - Password Does Not Expire - Not Delegated - Use DES Key Only',
          }

searchFlags = {'128' : 'Confidential',
               '640' : 'Confidential - RODC_Filtered',
               '664' : 'Preserve On Delete - Copy - Confidential - RODC_Filtered',
               '931' : 'Index - Container_Index - Tuple_Index - Confidential - Never_Audit_Value - RODC_Filtered',
              }

uacComputed = {'0' : 'Refer to userAccountControl Field',
               '16' : 'Locked Out',
               '8388608' : 'Password Expired',
               '8388624' : 'Locked Out - Password Expired',
               '67108864' : 'Partial Secrets Account',
               '2147483648' : 'Use AES Keys',
              }

encryptSupport = {'0' : '',
                  '28' : 'RC4_HMAC_MD5 - AES128_CTS_HMAC_SHA1_96 - AES256_CTS_HMAC_SHA1_96',
                  '31' : 'DES_CBC_CRC - DES_CBC_MD5 - RC4_HMAC_MD5 - AES128_CTS_HMAC_SHA1_96 - AES256_CTS_HMAC_SHA1_96',
                 }

groupTypeList = {'2' : 'Global Distribution Group',
                 '4' : 'Domain Local Distribution Group',
                 '8' : 'Universal Distribution Group',
                 '-2147483646' : 'Global Security Group',
                 '-2147483644' : 'Domain Local Security Group',
                 '-2147483643' : 'Built-In Local Security Group',
                 '-2147483640' : 'Universal Security Group',
                }

trustDirect = {'0' : 'Disabled',
               '1' : 'Inbound (Trusting Domain): This is a trusting domain or forest. The other domain or forest has access to the resources of this domain or forest. This domain or forest does not have access to resources that belong to the other domain or forest.',
               '2' : 'Outbound (Trusted Domain): This is a trusted domain or forest. This domain or forest has access to resources of the other domain or forest. The other domain or forest does not have access to the resources of this domain or forest.',
               '3' : 'Bidirectional (Two-Way Trust): Each domain or forest has access to the resources of the other domain or forest.',
              }

trustTyp = {'1' : 'Downlevel (Windows NT Domain External)',
            '2' : 'Uplevel (Active Directory Domain)',
            '3' : 'MIT (non-Windows) Kerberos Version 5 Realm',
            '4' : 'DCE (Open Group Distributed Computing Environment; Theoretical Trust)',
           }

trustAttribute = {'1' : 'Non-Transitive',
                  '2' : 'Up-level Trust (Windows 2000 and newer)',
                  '4' : 'Quarantined Domain External Trust (SID Filtering Enabled)',
                  '8' : 'Forest Trust',
                  '10' : 'Cross-Organizational Trust (Selective Authentication)',
                  '20' : 'Intra-Forest Trust (Trust within the Forest)',
                  '40' : 'Trust Attribute Treat As External',
                  '80' : 'Trust Attribute Uses RC4 Encryption',
                  '200' : 'Trust Attribute Cross Organization No TGT Delegation',
                  '400' : 'Trust Attribute PIM Trust',
                 }



def mainConversion():
    csvfile.seek(0)
    dictReader = csv.DictReader(csvfile)
    dictFields = dictReader.fieldnames
    dictFields.append('relativeIdentifier')
    listWriter = csv.DictWriter(open(fname[:-4] + '_output.csv', 'w', newline=''),
                fieldnames=dictFields,
                delimiter='|', quoting=csv.QUOTE_MINIMAL)
    listWriter.writeheader()
    for row in dictReader:
        if 'cn' in row:
            if (not "X'" in row["cn"][:2]):
                pass
            else:
                hex_string = row["cn"][2:-1]
                row["cn"] = binascii.unhexlify(hex_string).decode('utf8')

        if 'name' in row:
            if (not "X'" in row["name"][:2]):
                pass
            else:
                hex_string = row["name"][2:-1]
                row["name"] = binascii.unhexlify(hex_string).decode('utf8')

        if 'userAccountControl' in row:
            row["userAccountControl"] = options.get(row["userAccountControl"],
                                                    'Unknown Account Type')

        if 'lastLogonTimestamp' in row:
            if (not row["lastLogonTimestamp"]):
                pass
            elif int(row["lastLogonTimestamp"]) > 2:
                row["lastLogonTimestamp"] = (convert_ad_timestamp(row["lastLogonTimestamp"])
                                            .strftime("%Y-%m-%d %H:%M:%S"))
            else:
                row["lastLogonTimestamp"] = ''

        if 'pwdLastSet' in row:
            if (not row["pwdLastSet"]):
                pass
            elif int(row["pwdLastSet"]) > 0:
                row["pwdLastSet"] = (convert_ad_timestamp(row["pwdLastSet"])
                                    .strftime("%Y-%m-%d %H:%M:%S"))
            else:
                row["pwdLastSet"] = ''

        if 'accountExpires' in row:
            if int(row["accountExpires"]) == 0:
                row["accountExpires"] = ''
            elif int(row["accountExpires"]) > 922337203685477000:
                row["accountExpires"] = ''
            else:
                row["accountExpires"] = (convert_ad_timestamp(row["accountExpires"])
                                        .strftime("%Y-%m-%d %H:%M:%S"))

        if 'whenCreated' in row:
            row["whenCreated"] = (convert_generalized_timestamp(row["whenCreated"])
                                 .strftime("%Y-%m-%d %H:%M:%S"))

        if 'whenChanged' in row:
            row["whenChanged"] = (convert_generalized_timestamp(row["whenChanged"])
                                  .strftime("%Y-%m-%d %H:%M:%S"))

        if 'objectSid' in row:
            arrSid = row["objectSid"]
            arrSid = arrSid[2:-1]
            strSidDec = HexStrToDecStr(arrSid)
            row["objectSid"] = strSidDec
            row["relativeIdentifier"] = strSidDec.split('-')[-1]

        if 'member' in row:
            if (not row["member"]):
                pass
            else:
                memVal = row["member"]
                memVal_split = memVal.split(';')
                groupList = ''
                for x in memVal_split:
                    if ("X'" in x[:2]):
                        hex_string = x[2:-1]
                        x = binascii.unhexlify(hex_string).decode('utf8')
                    new_string = x.split(',')
                    jString = new_string[0]
                    fixString = jString[3:]
                    groupList = groupList + fixString + ", "
                finalList = groupList[:-2]
                row["member"] = finalList

        if 'memberOf' in row:
            if (not row["memberOf"]):
                pass
            else:
                memVal = row["memberOf"]
                memVal_split = memVal.split(';')
                groupList = ''
                for x in memVal_split:
                    if ("X'" in x[:2]):
                        hex_string = x[2:-1]
                        x = binascii.unhexlify(hex_string).decode('utf8')
                    new_string = x.split(',')
                    jString = new_string[0]
                    fixString = jString[3:]
                    groupList = groupList + fixString + ", "
                finalList = groupList[:-2]
                row["memberOf"] = finalList

        if 'msDS-PSOAppliesTo' in row:
            if (not row["msDS-PSOAppliesTo"]):
                pass
            else:
                memVal = row["msDS-PSOAppliesTo"]
                memVal_split = memVal.split(';')
                groupList = ''
                for x in memVal_split:
                    if ("X'" in x[:2]):
                        hex_string = x[2:-1]
                        x = binascii.unhexlify(hex_string).decode('utf8')
                    new_string = x.split(',')
                    jString = new_string[0]
                    fixString = jString[3:]
                    groupList = groupList + fixString + ", "
                finalList = groupList[:-2]
                row["msDS-PSOAppliesTo"] = finalList

        if 'searchFlags' in row:
            if (not row["searchFlags"]):
                pass
            else:
                row["searchFlags"] = searchFlags.get(row["searchFlags"],
                                      'Unknown Search Flag')

        if 'msDS-User-Account-Control-Computed' in row:
            if (not row["msDS-User-Account-Control-Computed"]):
                pass
            elif (row["pwdLastSet"] == '' and 'Password Not Required' in row["userAccountControl"]):
                row["msDS-User-Account-Control-Computed"] = 'Password is Blank'
            else:
                row["msDS-User-Account-Control-Computed"] = uacComputed.get(row["msDS-User-Account-Control-Computed"],
                                                            'Unknown Account Status')

        if 'msDS-UserPasswordExpiryTimeComputed' in row:
            if int(row["msDS-UserPasswordExpiryTimeComputed"]) == 0:
                row["msDS-UserPasswordExpiryTimeComputed"] = ''
            elif int(row["msDS-UserPasswordExpiryTimeComputed"]) > 922337203685477000:
                row["msDS-UserPasswordExpiryTimeComputed"] = ''
            else:
                row["msDS-UserPasswordExpiryTimeComputed"] = (convert_ad_timestamp(row["msDS-UserPasswordExpiryTimeComputed"])
                                        .strftime("%Y-%m-%d %H:%M:%S"))

        if 'lockoutTime' in row:
            if (not row["lockoutTime"]):
                pass
            elif row["lockoutTime"] == '0':
                row["lockoutTime"] = ''
            else:
                row["lockoutTime"] = convert_ad_timestamp(row["lockoutTime"])

        if 'msDS-MaximumPasswordAge' in row:
            if (not row["msDS-MaximumPasswordAge"]):
                pass
            elif row["msDS-MaximumPasswordAge"] == '-9223372036854775808':
                row["msDS-MaximumPasswordAge"] = ''
            else:
                row["msDS-MaximumPasswordAge"] = convert_fgpp_timestamp(row["msDS-MaximumPasswordAge"])

        if 'msDS-MinimumPasswordAge' in row:
            if (not row["msDS-MinimumPasswordAge"]):
                pass
            else:
                row["msDS-MinimumPasswordAge"] = convert_fgpp_timestamp(row["msDS-MinimumPasswordAge"])

        if 'msDS-LockoutObservationWindow' in row:
            if (not row["msDS-LockoutObservationWindow"]):
                pass
            else:
                row["msDS-LockoutObservationWindow"] = convert_fgpp_timestamp(row["msDS-LockoutObservationWindow"])

        if 'msDS-LockoutDuration' in row:
            if (not row["msDS-LockoutDuration"]):
                pass
            else:
                row["msDS-LockoutDuration"] = convert_fgpp_timestamp(row["msDS-LockoutDuration"])

        if 'msDS-SupportedEncryptionTypes' in row:
            if (not row["msDS-SupportedEncryptionTypes"]):
                pass
            else:
                row["msDS-SupportedEncryptionTypes"] = encryptSupport.get(row["msDS-SupportedEncryptionTypes"],
                                                       'Unknown Search Flag')

        if 'groupType' in row:
            if (not row["groupType"]):
                pass
            else:
                row["groupType"] = groupTypeList.get(row["groupType"],
                                   'Unknown Group Type')

        if 'trustDirection' in row:
            if (not row["trustDirection"]):
                pass
            else:
                row["trustDirection"] = trustDirect.get(row["trustDirection"],
                                                        'Unknown Trust Direction')

        if 'trustType' in row:
            if (not row["trustType"]):
                pass
            else:
                row["trustType"] = trustTyp.get(row["trustType"],
                                                'Unknown Trust Type')

        if 'trustAttributes' in row:
            if (not row["trustAttributes"]):
                pass
            else:
                row["trustAttributes"] = trustAttribute.get(row["trustAttributes"],
                                                            'Unknown Trust Attibute')

        if 'operatingSystem' in row:
            if (not "X'" in row["operatingSystem"][:2]):
                pass
            else:
                hex_string = row["operatingSystem"][2:-1]
                row["operatingSystem"] = binascii.unhexlify(hex_string).decode('utf8')

        listWriter.writerow(row)

def convert_generalized_timestamp(timestamp):
    year = int(timestamp[:4])
    month = int(timestamp[4:6])
    day = int(timestamp[6:8])
    hour = int(timestamp[8:10])
    minute = int(timestamp[10:12])
    second = int(timestamp[12:14])

    fullTimestamp = datetime(year, month, day, hour, minute, second)
    fixedTimestamp = fullTimestamp - timedelta(hours=7)
    return fixedTimestamp

def convert_ad_timestamp(timestamp):
    #Found at timestamp.ooz.ie/p/time-in-python.html
    #Modified for Arizona Time by Alex Entringer 10/01/14
    epoch_start = datetime(year=1601, month=1,day=1)
    seconds_since_epoch = int(timestamp)/10**7
    return epoch_start + timedelta(seconds=seconds_since_epoch) - timedelta(hours=7)

def convert_fgpp_timestamp(timestamp):
    days = float(timestamp) / 10000000 / (-86400)
    hours = days%1
    hours = hours * 24
    minutes = hours%1
    hours = hours - minutes
    minutes = minutes * 60
    seconds = minutes%1
    minutes = minutes - seconds
    seconds = int(seconds * 60)

    if days < 1:
        days = 0

    fixedTimestamp = (str(days) + ' day(s), ' + str(hours) + ' hour(s), ' +
                     str(minutes) + ' minutes, ' + str(seconds) + ' seconds')
    return fixedTimestamp

def ReSortSid(sidPiece):
    #Originally written by Francisco Puig
    #Obtained from (http://poshcode.org/3385)
    #Converted to Python by Alex Entringer 7/7/2016
    a = sidPiece[0:2]
    b = sidPiece[2:4]
    c = sidPiece[4:6]
    d = sidPiece[6:8]
    final = d + c + b + a
    return final

def HexStrToDecStr(arrSid):
    #Originally written by Francisco Puig
    #Obtained from (http://poshcode.org/3385)
    #Converted to Python by Alex Entringer 7/7/2016
    try:
        sidRevision = str(int(arrSid[0:2]))
        identifierAuthority = str(int(arrSid[2:4]))
        securityNTNonUnique = str(int(ReSortSid(arrSid[16:24]),16))
        sidPortion1 = arrSid[24:32]
        sidPortion2 = arrSid[32:40]
        if (not sidPortion2):
            machineID1 = str(int(ReSortSid(sidPortion1),16))
            stringSid = 'S-' + sidRevision + '-' + identifierAuthority + '-' + securityNTNonUnique + '-' + machineID1
            return stringSid
        else:
            sidPortion3 = arrSid[40:48]
            sidPortion4 = arrSid[48:56]
            machineID1 = str(int(ReSortSid(sidPortion1),16))
            machineID2 = str(int(ReSortSid(sidPortion2),16))
            machineID3 = str(int(ReSortSid(sidPortion3),16))
            uid = str(int(ReSortSid(sidPortion4),16))
            stringSid = 'S-' + sidRevision + '-' + identifierAuthority + '-' + securityNTNonUnique + '-' + machineID1 + '-' + machineID2 + '-' + machineID3 + '-' + uid
            return stringSid
    except IndexError:
        return stringSid

if __name__ == '__main__':
    dirListing = os.listdir(os.getcwd())

    for fname in dirListing:
        try:
            if (os.path.isfile(fname) and fname.endswith(".csv")):
                print('=======================================================================')
                print('Beginning conversion of ',fname)
                with fileinput.input(fname,inplace=True,backup='.backup') as f:
                    for line in f:
                        line = line.replace("|","-")
                        print(line, end='')

                with open(fname, 'r', newline='') as csvfile:
                    mainConversion()

                os.remove(fname)
                os.rename(fname + '.backup',fname)
                print('Finished converting ',fname)
                print('=======================================================================')
                print()
        except UnicodeDecodeError:
            if (os.path.isfile(fname) and fname.endswith(".csv")):
                print('=======================================================================')
                print('Beginning conversion of ',fname)
                with fileinput.input(fname,inplace=True,backup='.backup') as f:
                    for line in f:
                        line = line.replace("|","-")
                        print(line, end='')

                with open(fname, 'r', newline='', encoding='iso-8859-1') as csvfile:
                    mainConversion()

                os.remove(fname)
                os.rename(fname + '.backup',fname)
                print('Finished converting ',fname)
                print('=======================================================================')
                print()
