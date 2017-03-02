
#=================================================================================================================================
# Make CA Bundle Offline - For Mozilla Certificate Data

# Python version (c) Rudy Yusuf ( rudyy.id@gmail.com ), 2017.
# Base on Perl version in cURL source ( https://curl.haxx.se/ ).
#
# If you're using this for commercial product please send an email to me before using it or copy my code.
#
# This version has been improve beyond Perl version.
# The improvement include:
# - Label didn't contain a Backslash character.
#   Any backslash character has been translating into UTF-8 if its a hex value (\x).
#   Any backslash character without a hex (non \x) will be written as the way it was (the idea based on OpenSSL and/or RFC).
# - Completely align certificate based on OpenSSL rule or RFC rule.
# - Open "Mozilla Certificate Data" file in binary mode and save "CA Bundle" in binary mode.
#   This resolve the issue with "Mozilla Certificate Data" file contain backslash character.
# - etc.
#
# The Limitation are:
# - Only work on an offline "Mozilla Certificate Data" file.
# - Can not process if "Mozilla Certificate Data" file in unicode or encode with BOM.
#   Make sure "Mozilla Certificate Data" file format in UTF-8 Without BOM.
# - Only save a CA only. Non CA will not be save.
#
# Consideration:
# - Look in main(argv) if you have different path name rule (eg, '\' or '/').
#
# Mozilla Certificate Data can be download from:
# - nss     => https://hg.mozilla.org/projects/nss/raw-file/tip/lib/ckfw/builtins/certdata.txt
# - central => https://hg.mozilla.org/mozilla-central/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt
# - aurora  => https://hg.mozilla.org/releases/mozilla-aurora/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt
# - beta    => https://hg.mozilla.org/releases/mozilla-beta/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt
# - release => https://hg.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt
#=================================================================================================================================

import sys
import os
import re
import binascii

MozillaTrustReqPrimary = [ 'DIGITAL_SIGNATURE', 'NON_REPUDIATION', 'KEY_ENCIPHERMENT', 'DATA_ENCIPHERMENT',
						 'KEY_AGREEMENT', 'KEY_CERT_SIGN', 'CRL_SIGN', 'SERVER_AUTH', 'CLIENT_AUTH',
						 'CODE_SIGNING', 'EMAIL_PROTECTION', 'IPSEC_END_SYSTEM', 'IPSEC_TUNNEL',
						 'IPSEC_USER', 'TIME_STAMPING' ]
MozillaTrustReqPrimaryType = 'CK_TRUST'

MozillaTrustReqBool = [ 'STEP_UP_APPROVED' ]
MozillaTrustReqBoolType = 'CK_BBOOL'

MozillaTrustLevels = [ 'TRUSTED_DELEGATOR', # CAs
					   'MUST_VERIFY_TRUST', # This explicitly tells us that it ISN'T a CA but is otherwise ok.
											# In other words, this should tell the app to ignore any other sources that claim this is a CA.
					   'TRUSTED',           # This cert is trusted, but only for itself and not for delegates (i.e. it is not a CA).
					   'NOT_TRUSTED'        # Don't trust these certs.
					 ]

CertHeader = '-----BEGIN CERTIFICATE-----'
CertFooter = '-----END CERTIFICATE-----'

FStyleNL = '\n'
FStyleLabelUR = '='

EmptyString = ''

ErrorMainList = [ '\nError. Creating RE Object.\n' ]

ErrorReadList = [ '\nError. Read "CKA_LABEL UTF8" value. Line %d.\n',
				  '\nError. Read "CKA_VALUE MULTILINE_OCTAL" value. Line %d.\n',
				  '\nError. Read "CKA_TRUST_" value. Line %d.\n' ]

ErrorEncodeList = [ '    ',
					'Error. Converting line %d into UTF-8 encoding.\n',
					'Trying another method...',
					'Result: OK.', 'Result: Failed.' ]

ProgVersion = '0.30'

def ListClean(ListObj):
	ListLen = 0
	if ListObj:
		ListLen = len(ListObj)
		while ListLen != 0:
			ListObj.pop()
			ListLen -= 1

def ListRemoveEmpty(ListObj):
	I = 0
	ListLen = 0
	if ListObj:
		ListLen = len(ListObj)
		while ListLen != I:
			if not ListObj[I]:
				ListObj.pop(I)
				ListLen -= 1
				continue
			I += 1

def CertToBase64(StrChar, IncHF=False, IncNL=False):
	## [MaxColumnNumber] * 3 / 4
	##                           -> OpenSSL: [64] * 3 / 4 = 48
	MaxEnc = 48
	EncList = list()
	VarLen = 0
	I = 0
	J = I
	try:
		if IncHF:
			EncList.append(CertHeader)
		if IncNL:
			EncList.append(FStyleNL)
		VarLen = len(StrChar)
		if MaxEnc > VarLen:
			MaxEnc = VarLen
		while VarLen > I:
			J = I + MaxEnc
			if J > VarLen:
				J = VarLen
			EncList.append(binascii.b2a_base64(StrChar[I:J])[:-1])
			if IncNL:
				EncList.append(FStyleNL)
			I = J
		if IncHF:
			EncList.append(CertFooter)
		if IncNL:
			EncList.append(FStyleNL)
	except:
		ListClean(EncList)
	return EncList

def CorrectCertLabel(InStr):
	OutStr = ''
	InStrLen = 0
	I = 0
	if not InStr:
		return InStr
	InStrLen = len(InStr)
	while InStrLen > I:
		if InStr[I:I + 1] == '\\':
			I += 1
			if InStr[I:I + 1] == 'x':
				I += 1
				OutStr += chr(int(InStr[I:I + 2], 16))
				I += 2
				continue
		OutStr += InStr[I:I + 1]
		I += 1
	return OutStr

def WriteCert(ProgPath, InputName, OutputName, IsLabelInOutput=True, DoEncode=False):
	TempStr = ''
	RawLine = ''
	EncodeLine = ''
	CleanLine = ''
	I = 0
	VarLen = 0
	ListObj = None
	ReObj = None
	
	FileLineNo = 0
	ErrorNumber = 0
	CertBegin = False
	DataBegin = False
	DataEnd = False
	TrustBegin = False
	LabelPrinted = False
	
	CertReObj = re.compile('CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE', re.IGNORECASE)
	if not CertReObj:
		print(ErrorMainList[0])
		return 254
	LabelStr = ''
	LabelReObj = re.compile(r'CKA_LABEL UTF8 \"([^\"]+)\"', re.IGNORECASE)
	if not LabelReObj:
		re.purge()
		print(ErrorMainList[0])
		return 254
	DataRawStr = ''
	DataEncSplit = None
	DataReObj = re.compile('CKA_VALUE MULTILINE_OCTAL', re.IGNORECASE)
	if not DataReObj:
		re.purge()
		print(ErrorMainList[0])
		return 254
	OctetsReObj = re.compile('[0-7][0-7][0-7]', re.IGNORECASE)
	if not OctetsReObj:
		re.purge()
		print(ErrorMainList[0])
		return 254
	EndReObj = re.compile('END', re.IGNORECASE)
	if not EndReObj:
		re.purge()
		print(ErrorMainList[0])
		return 254
	
	TrustReObj = re.compile('CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST', re.IGNORECASE)
	if not TrustReObj:
		print(ErrorMainList[0])
		return 254
	TrustPurpose = ''
	TrustLevel = ''
	TrustPrimaryReObj = re.compile(r'CKA_TRUST_([a-z_]+) CK_TRUST CKT_NSS_([a-z_]+)', re.IGNORECASE)
	if not TrustPrimaryReObj:
		print(ErrorMainList[0])
		return 254
	
	try:
		os.remove(OutputName)
		print('Deleted file "%s".' % OutputName)
	except:
		pass
	FTxtInObj = open(InputName, 'rb')
	FTxtOutObj = open(OutputName, 'wb')
	
	for RawLine in FTxtInObj:
		FileLineNo += 1
		if DoEncode:
			try:
				EncodeLine = RawLine.encode('utf_8', 'strict')
			except:
				try:
					EncodeLine = ''
					if LabelPrinted:
						TempStr = ErrorEncodeList[0] + ErrorEncodeList[1] + ErrorEncodeList[0] + ErrorEncodeList[2]
					else:
						TempStr = '\n' + ErrorEncodeList[1] + ErrorEncodeList[0] + ErrorEncodeList[2]
					print(TempStr % FileLineNo)
					TempStr = ''
					EncodeLine = RawLine.encode('utf_8', 'ignore')
					if LabelPrinted:
						TempStr = ErrorEncodeList[0]
					TempStr += ErrorEncodeList[0] + ErrorEncodeList[4]
					print(TempStr)
					TempStr = ''
				except:
					try:
						EncodeLine = RawLine
						if LabelPrinted:
							TempStr = ErrorEncodeList[0]
						TempStr += ErrorEncodeList[0] + ErrorEncodeList[4]
						if not LabelPrinted:
							TempStr += '\n'
						print(TempStr)
						TempStr = ''
					except:
						ErrorNumber = 250
						break
			ListObj = EncodeLine.splitlines(False)
			EncodeLine = ''
		else:
			ListObj = RawLine.splitlines(False)
		ListRemoveEmpty(ListObj)
		if not ListObj:
			if DataBegin:
				try:
					print(ErrorReadList[1] % FileLineNo)
				finally:
					ErrorNumber = 3
					break
			continue
		CleanLine = ListObj[0].strip()
		ListClean(ListObj)
		if (not CleanLine) or (CleanLine == '#'):
			if DataBegin:
				try:
					print(ErrorReadList[1] % FileLineNo)
				finally:
					ErrorNumber = 3
					break
			continue
		if CertBegin:
			if not DataBegin:
				if CertReObj.match(CleanLine):
					ListClean(DataEncSplit)
					DataRawStr = ''
					LabelStr = ''
					TrustBegin = False
					DataEnd = False
					DataBegin = False
					if LabelPrinted:
						LabelPrinted = False
						print('    CANCELING. Found NON CA. Line %d.' % FileLineNo)
				else:
					if not TrustBegin:
						if not DataEnd:
							if not LabelStr:
								try:
									ReObj = LabelReObj.match(CleanLine)
									if ReObj:
										LabelStr = ReObj.group(1)
										if not LabelStr:
											raise ValueError
										else:
											LabelPrinted = True
											LabelStr = CorrectCertLabel(LabelStr)
											print('\nCertificate on Line %d\n    "%s"' % (FileLineNo, LabelStr))
											VarLen = len(LabelStr)
											LabelStr += FStyleNL
											for I in range(0, VarLen, 1):
												LabelStr += FStyleLabelUR
											LabelStr += FStyleNL
								except:
									try:
										print(ErrorReadList[0] % FileLineNo)
									finally:
										ErrorNumber = 2
										break
							elif DataReObj.match(CleanLine):
								DataBegin = True
						elif TrustReObj.match(CleanLine):
							TrustBegin = True
					else:
						try:
							ReObj = TrustPrimaryReObj.match(CleanLine)
							if ReObj:
								TrustPurpose = ReObj.group(1).upper()
								TrustLevel = ReObj.group(2).upper()
								if (TrustPurpose in MozillaTrustReqPrimary) and (TrustLevel == MozillaTrustLevels[0]):
									FTxtOutObj.write(FStyleNL)
									if IsLabelInOutput:
										FTxtOutObj.write(LabelStr)
									for I in range(0, len(DataEncSplit), 1):
										FTxtOutObj.write(DataEncSplit[I])
									FTxtOutObj.flush()
									ListClean(DataEncSplit)
									DataRawStr = ''
									LabelStr = ''
									LabelPrinted = False
									TrustBegin = False
									DataEnd = False
									DataBegin = False
									CertBegin = False
									print('    SAVE.')
								TrustLevel = ''
								TrustPurpose = ''
						except:
							try:
								print(ErrorReadList[2] % FileLineNo)
							finally:
								ErrorNumber = 4
								break
			else:
				if EndReObj.match(CleanLine):
					try:
						DataEncSplit = CertToBase64(DataRawStr, True, True)
						DataRawStr = ''
						if not DataEncSplit:
							raise ValueError
					except:
						try:
							print(ErrorReadList[1] % FileLineNo)
						finally:
							ErrorNumber = 250
							break
					DataBegin = False
					DataEnd = True
				else:
					try:
						ListObj = CleanLine.split('\\')
						if not ListObj:
							raise ValueError
					except:
						try:
							print(ErrorReadList[1] % FileLineNo)
						finally:
							ErrorNumber = 250
							break
					ListRemoveEmpty(ListObj)
					if not ListObj:
						try:
							print(ErrorReadList[1] % FileLineNo)
						finally:
							ErrorNumber = 3
							break
					for I in range(0, len(ListObj), 1):
						if not OctetsReObj.match(ListObj[I]):
							ErrorNumber = 3
							break
						try:
							DataRawStr += chr(int(ListObj[I], 8))
						except:
							ErrorNumber = 3
							break
					ListClean(ListObj)
					if ErrorNumber:
						try:
							print(ErrorReadList[1] % FileLineNo)
						finally:
							break
		elif CertReObj.match(CleanLine):
			CertBegin = True
	
	FTxtOutObj.close()
	FTxtInObj.close()
	re.purge()
	return ErrorNumber

def main(argv):
	FObj = None
	NextParam = ''
	I = 0
	
	ProgPath = ''
	CertFName = ''
	BundleFName = ''
	IsPrintLabel = True
	IsCustomOutput = False
	
	try:
		ProgPath = os.path.dirname(os.path.realpath(str(argv[0])))
		CertFName = os.path.realpath(str(argv[1]))
		if os.path.isdir(ProgPath) and os.path.isfile(CertFName):
			BundleFName = ProgPath + '\\CABundle.pem'
			FObj = open(CertFName, 'rb')
			FObj.close()
			for I in range(2, 4, 1):
				try:
					NextParam = str(argv[I])
				except:
					break
				if (NextParam == '-l') or (NextParam == '-L'):
					if not IsPrintLabel:
						raise IndexError
					IsPrintLabel = False
				else:
					if not IsCustomOutput:
						IsCustomOutput = True
						BundleFName = ''
						try:
							FObj = open(NextParam, 'wb')
							BundleFName = os.path.realpath(FObj.name)
							FObj.close()
							os.remove(BundleFName)
						except:
							raise IndexError
					else:
						raise IndexError
		else:
			raise IOError
	except IOError:
		print('\nMake CA Bundle - Version %s\n-----------------------------\n\nCan not open Mozilla Certificates Data file!!\n' % ProgVersion)
		return 1
	except IndexError:
		print('\nMake CA Bundle - Version %s\n-----------------------------\n\n'
			  'Usage:\n       MKCABundle_Offline [certdata.txt] [OutputFileName] [-L]\n'
			  '       \n       OutputFileName : If itsn\'t supply, the default will be "CABundle.pem".\n'
			  '       -L              : Don\'t put label in output file.' % ProgVersion)
		return 1
	
	NextParam = ''
	print('\nMake CA Bundle - Version %s\n-----------------------------\n\nProcessing "%s"...\n' % (ProgVersion, CertFName))
	return WriteCert(ProgPath, CertFName, BundleFName, IsPrintLabel)

if __name__ == '__main__':
	sys.exit(main(sys.argv))
