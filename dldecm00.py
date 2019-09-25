#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
dl and dec books
"""

import sys
import os
import io
import shutil
import platform
import sqlite3
import json
import glob
import requests
import zipfile
from zipfile import ZipInfo, ZipFile, ZIP_STORED, ZIP_DEFLATED
import base64
import xml.etree.ElementTree as etree
from contextlib import closing
from clint.textui import progress

from caesarcipher import CaesarCipher

SECRET1 = CaesarCipher( "Ernqzbb", -13 )
SECRET2 = CaesarCipher( "ylhktvv", -7 )
SECRET3 = CaesarCipher( "raxtci_xs", -15 )
SECRET4 = CaesarCipher( "lnnpdd_ezvpy", -11 )
SECRET5 = CaesarCipher( "byrhqho_yjuc", -16 )

APP_TITLE = SECRET1 + CaesarCipher( " Huuqy Juctrugjkx & Jkixevzux", -6 )
APP_VERSION = "v1.0"

ENCRYPTION_XML = "META-INF/encryption.xml"
MIMETYPE = 'mimetype'
META_NAMES = (MIMETYPE, ENCRYPTION_XML)
NSMAP = {'enc' : 'http://www.w3.org/2001/04/xmlenc#'}

DB_DIR = os.path.join( SECRET1, CaesarCipher( "Uxlju Bcxajpn", -9 )  )
DB_FILE_NAME = "app_" + SECRET2 + "_0." + CaesarCipher( "ruigryzuxgmk", -6 )

DEC_BOOKS_DIR = CaesarCipher( "WirQngwfwd", -5 )
ENC_BOOKS_DIR = os.path.join( DEC_BOOKS_DIR, "enc" )

EXT_EPUB = ".epub"

DOWNLOAD_SHEET = SECRET1 + "Books.txt"
DOWNLOAD_SHEET_BAK = SECRET1 + "Books.bak"

gRsaKey = None
gUserId = None
gAccessToken = None
gClientId = None
gBookData = dict()
gArchiveData = dict()
gDlBooks = []

def _load_crypto_pycryptodome():
	"""
	Try to load RSA, AES decryption routine from PyCryptodome module
	"""
	from Crypto.PublicKey.RSA import import_key as _import_key		# import_key in PyCryptodome but not in PyCrypto
	from Crypto.Cipher import AES as _AES
	from Crypto.PublicKey import RSA as _RSA
	from Crypto.Cipher import PKCS1_v1_5 as _PKCS1

	class AES(object):
		def __init__(self, key, iv):
			self._aes = _AES.new(key, _AES.MODE_CBC, iv)

		def decrypt(self, data):
			return self._aes.decrypt(data)

	class RSA(object):
		def __init__(self, der):
			key = _import_key( der )
			self._rsa = _PKCS1.new(key)

		def decrypt(self, data):
			return self._rsa.decrypt(data, None)
	
#	print( "Use PyCryptodome for RSA/AES function" )
	return (AES, RSA)


def SystemChecking():
	if not sys.platform.startswith('win'):
		print( "[E] This program is for Windows only!" )
		return False

	if platform.release() == "XP":
		print( "[E] Windows XP is not supported!" )
		return False

	if sys.version_info.major < 3:
		print( "[E] Python 3 is required!" )
		return False

	return True

def CollectBookInfo():
	global gAccessToken, gClientId, gRsaKey, gUserId
	global gArchiveData, gBookData

	localAppData = os.getenv( "LOCALAPPDATA" )
	
	dbFile = os.path.join( localAppData, DB_DIR, DB_FILE_NAME )
	if not os.path.isfile( dbFile ):
		print( "[E] Can't find DB file! (" + SECRET1 + " application not installed?)" )
		return False

	conn = sqlite3.connect( dbFile )
	cursor = conn.execute( CaesarCipher( "COVOMD fkveo PBYW SdowDklvo GROBO uoi='__yk__'", -10 ) )
	data = cursor.fetchone()
	if not data:
		print( "[E] Can't get data from DB!" )
		return False
	else:
		jsObj = json.loads( data[0].decode( "utf-16-le" ) )
		gAccessToken = jsObj[ SECRET2 ][ SECRET4 ]
		gClientId = jsObj[ SECRET2 ][ SECRET3 ]

	cursor = conn.execute( CaesarCipher( "KWDWUL nsdmw XJGE AlweLstdw OZWJW cwq='jks_hjanslwCwq'", -18 ) )
	data = cursor.fetchone()
	if not data:
		print( "[E] Can't get data from DB!" )
		return False
	else:
		privateKey = data[0].decode( "utf-16-le" )
		gRsaKey = RSA( privateKey )

	cursor = conn.execute( CaesarCipher( "AMTMKB ditcm NZWU QbmuBijtm EPMZM smg='-ve-camzql'", -8 ) )
	data = cursor.fetchone()
	if not data:
		print( "[E] Can't get data from DB!" )
		return False
	else:
		gUserId = data[0].decode( "utf-16-le" )

	cursor = conn.execute( CaesarCipher( "KWDWUL nsdmw XJGE AlweLstdw OZWJW cwq='-fo-datjsjq'", -18 ) )
	data = cursor.fetchone()
	if not data:
		print( "[E] Can't get data from DB!" )
		return False
	else:
		jsObj = json.loads( data[0].decode( "utf-16-le" ) )
		for item in jsObj:
			bookId = item[ SECRET5 ][ "book" ][ "id" ]
			bookTitle = item[ SECRET5 ][ "book" ][ "title" ]
			bookAuthor = item[ SECRET5 ][ "book" ][ "author" ]
			bookPub = item[ SECRET5 ][ "book" ][ "publisher" ]
			if item[ "action" ] == "archive":
				gArchiveData.update( { bookId : [ bookTitle, bookAuthor, bookPub ] } )
			else:
				gBookData.update( { bookId : [ bookTitle, bookAuthor, bookPub ] } )

	conn.close()

	return True

def CheckBookDir():
	if not os.path.exists( ENC_BOOKS_DIR ):
		try:
			os.makedirs( ENC_BOOKS_DIR )
		except:
			print( "[E] Can't create directory: " + os.path.abspath( ENC_BOOKS_DIR ) )
			return False

		print( "[I] Create directory: " + os.path.abspath( DEC_BOOKS_DIR ) )
	
	return True

def GetDlBooks():
	global gDlBooks
	
	for f in glob.glob( os.path.join( ENC_BOOKS_DIR, "*.epub" ) ):
		gDlBooks.append( os.path.splitext( os.path.basename( f ) )[0] )

def DownloadSheetExist():
	return os.path.isfile( DOWNLOAD_SHEET )

def GenerateDownloadSheet():
	GetDlBooks()

	dled = 0
	total = 0
	archive = 0
	try:
		with open( DOWNLOAD_SHEET, "w", encoding="utf8" ) as f:
			f.write( "#\n" )
			f.write( "# List of books on " + SECRET1 + "\n" )
			f.write( "#\n" )
			f.write( "# [V] : already downloaded\n" )
			f.write( "# [ ] : not downloaded yet\n" )
			f.write( "# [A] : archive\n" )
			f.write( "#\n" )
			f.write( "# Actions:\n" )
			f.write( "#   [*] : download this book\n" )
			f.write( "#   [D] : decrypt this book\n" )
			f.write( "#\n\n" )

			for k in gBookData.keys():
				total = total + 1
				if k in gDlBooks:
					line = "[V] "
					dled = dled + 1
				else:
					line = "[ ] "
				line = line + "{:15s} {:s}\n".format( k, gBookData[ k ][ 0 ] )
				f.write( line )

			f.write( "\n" )

			for k in gArchiveData.keys():
				archive = archive + 1
				if k in gDlBooks:
					line = "[O] "
					dled = dled + 1
				else:
					line = "[A] "
				line = line + "{:15s} {:s}\n".format( k, gArchiveData[ k ][ 0 ] )
				f.write( line )
	except IOError as e:
		print( "[E] Can't write download sheet!" )
		return False

	print( "[I] Download sheet file '" + DOWNLOAD_SHEET + "' generated" )
	print( "      Books      : " + str( total ) )
	print( "      Downloaded : " + str( dled ) )
	print( "      Archive    : " + str( archive ) )

	return True

def DownloadBook( bookId ):
	if not bookId in gBookData.keys():
		print( "[E] You don't have book " + bookId + " !" )
		return False

	print( "[I] Download book: " + bookId )
	downloadEpubUrl = "https://api." + SECRET2 + ".com/epub/" + bookId + "?" + SECRET3 + "=" + gClientId + "&" + SECRET4 + "=" + gAccessToken
	response = requests.get( downloadEpubUrl, stream = True )
	bookFile = os.path.join( ENC_BOOKS_DIR, bookId + EXT_EPUB )
	if os.path.isfile( bookFile ):
		print( "[N]   Overwrite existing ePub file" )

	try:
		with open( bookFile, "wb" ) as f:
			total_length = int( response.headers.get( "content-length" ) )
			chunk_size = 1024
			expected_size = (total_length / chunk_size) + 1
			for chunk in progress.bar( response.iter_content( chunk_size = chunk_size ), expected_size = expected_size ):
				if chunk:
					f.write( chunk )
					f.flush()
	except:
		print( "[E]   Can't save file!" )
		if os.path.isfile( bookFile ):
			os.remove( bookFile )
		return False

	if response.status_code == 200:
		return True
	else:
		print( "[E]   Can't download book. Status code = " + str( response.status_code ) )
		return False

class Decryptor(object):
	"""
	This class is used to decrypt ePub file.	
	"""

	def __init__(self, bookkey, encryption):
		"""
		Parameters:
			bookkey(str) : AES key for decrypting book content
			encryption(str) : content of the file META-INF/encryption.xml
		"""
		self._bookkey = bookkey

		self._encrypted = encrypted = set()
		enc = lambda tag: '{%s}%s' % (NSMAP['enc'], tag)
		refExpr = './%s/%s/%s' % (enc('EncryptedData'), enc('CipherData'), enc('CipherReference'))

		# construct the list of encrypted files
		for elem in encryption.findall(refExpr):
			path = elem.get('URI', None)
			if path is not None:
				path = path.encode('utf-8')
				encrypted.add(path)

		print( "      Number of encrypted files = {0}".format(len(encrypted)) )

	def decrypt(self, path, data):
		"""
		Call this function with file name and its content.
		If the file is listed as encrypted, the file content will be decrypted and returned.
		Otherwise original content will be returned.

		Parameters:
			path(str) : file name
			data(str) : file content

		Returns:
			decrypted content
		"""
		if path.encode('utf-8') in self._encrypted:
			data = AES(self._bookkey, data[0:16]).decrypt(data[16:])
			numPadding = data[-1]
			if (numPadding > 0) and (numPadding <= 16):
				data = data[ : numPadding * -1]
		return data


def DecryptBook( bookId ):
	print( "[I] Decrypt book: " + bookId )

	encFile = os.path.join( ENC_BOOKS_DIR, bookId + EXT_EPUB )
	decFile = os.path.join( DEC_BOOKS_DIR, bookId + EXT_EPUB )

	if not os.path.isfile( encFile ):
		print( "[E]   File not found: " + encFile )
		return False

	if not CheckEpubIntegrity( bookId ):
		print( "[E]   Can't open ePub file! (Re-download)" )
		return False

	with closing( ZipFile( open( encFile, "rb" ) ) ) as inf:
		namelist = set( inf.namelist() )

		if ENCRYPTION_XML not in namelist:
			print( "[W]   Can't find " + ENCRYPTION_XML + ". Assume it's DRM-free book" )
			if os.path.isfile( decFile ):
				os.remove( decFile )
			shutil.copyfile( encFile, decFile )
			return True

		for name in META_NAMES:
			namelist.remove(name)

		try:
			# get book AES key from META-INF/encryption.xml
			encryption = etree.fromstring( inf.read( ENCRYPTION_XML ) )
			enc = lambda tag: '{%s}%s' % (NSMAP['enc'], tag)
			keyExpr = './/%s' % (enc('CipherValue'))
			aesKeyB64 = encryption.findtext(keyExpr)
			if aesKeyB64 is None:
				print( "[E]   Can't find encrypted AES key!" )
				return False

			bookkey = gRsaKey.decrypt( base64.b64decode( aesKeyB64 ) )
			if bookkey is None:
				print( "[E]   Can't decrypt AES key!" )
				return False

			print( "      AES KEY = {0}".format( ''.join( hex( x )[2:].zfill( 2 ) for x in bookkey).upper() ) )

			decryptor = Decryptor( bookkey, encryption )
			kwds = dict( compression=ZIP_DEFLATED, allowZip64=False )
			with closing( ZipFile( open( decFile, 'wb' ), 'w', **kwds ) ) as outf:
				zi = ZipInfo( MIMETYPE )
				zi.compress_type = ZIP_STORED
				try:
					# if the mimetype is present, get its info, including time-stamp
					oldzi = inf.getinfo(MIMETYPE)
					# copy across fields to be preserved
					zi.date_time = oldzi.date_time
					zi.comment = oldzi.comment
					zi.extra = oldzi.extra
					zi.internal_attr = oldzi.internal_attr
					# external attributes are dependent on the create system, so copy both.
					zi.external_attr = oldzi.external_attr
					zi.create_system = oldzi.create_system
				except:
					pass
				outf.writestr( zi, inf.read( MIMETYPE ) )
				
				# process files in ePub
				for path in namelist:
					data = inf.read( path )
					zi = ZipInfo( path )
					zi.compress_type = ZIP_DEFLATED
					try:
						# get the file info, including time-stamp
						oldzi = inf.getinfo( path )
						# copy across useful fields
						zi.date_time = oldzi.date_time
						zi.comment = oldzi.comment
						zi.extra = oldzi.extra
						zi.internal_attr = oldzi.internal_attr
						# external attributes are dependent on the create system, so copy both.
						zi.external_attr = oldzi.external_attr
						zi.create_system = oldzi.create_system
					except:
						pass
					outf.writestr( zi, decryptor.decrypt( path, data ) )
		except Exception as e:
			print( "[E]   Can't decrypt book! (" + str( e ) + ")" )
			return False

	RenameBook( bookId )

	return True

def RenameBook( bookId ):
	if not bookId in gBookData.keys():
		print( "[E] Can't rename book: wrong book ID " + bookId )
		return False

	decFile = os.path.join( DEC_BOOKS_DIR, bookId + EXT_EPUB )
	titleFile = os.path.join( DEC_BOOKS_DIR, gBookData[ bookId ][0] + EXT_EPUB )
	if os.path.isfile( titleFile ):
		os.remove( titleFile )
	print( "[I] Rename " + bookId + EXT_EPUB + " -> " + gBookData[ bookId ][0] + EXT_EPUB )
	os.rename( decFile, titleFile )

	return True

def GetBook( bookId ):
	if not DownloadBook( bookId ):
		return False

	if not DecryptBook( bookId ):
		return False

	return True

def CheckEpubIntegrity( bookId ):
	bookFile = os.path.join( ENC_BOOKS_DIR, bookId + EXT_EPUB )
	
	try:
		zf = zipfile.ZipFile( bookFile )
		ret = zf.testzip()
		if ret is None:
			return True
		else:
			return False
	except:
		return False


def ProcessDownloadSheet():
	if not DownloadSheetExist():
		print( "[E] Download sheet not exist!" )
		return False

	print( "[I] Parse download sheet" )
	todl = []
	todec = []
	try:
		for line in open( DOWNLOAD_SHEET, "r", encoding="utf8" ):
			if line.startswith( "[" ):
				mark = line[1]
				id = line[4:19]
				if mark == "*":
					todl.append( id )
				elif mark.lower() == "d":
					todec.append( id )
	except IOError as e:
		print( "[E] Can't read download sheet!" )
		return False

	bDoSomething = False

	if len( todec ) > 0:
		print( "[I] Books to be decrypted: " + str( len( todec ) ) )
		decok = 0
		decng = 0
		for bookId in todec:
			if DecryptBook( bookId ):
				decok = decok + 1
			else:
				decng = decng + 1
				todl.append( bookId )

		print( "[I] Decrypt Done" )
		print( "      OK: " + str( decok ) )
		print( "    Fail: " + str( decng ) )
		print( "" )
		bDoSomething = True


	if len( todl ) > 0:
		print( "[I] Books to be downloaded: " + str( len( todl ) ) )
		dlok = 0
		dlng = 0
		for bookId in todl:
			if GetBook( bookId ):
				dlok = dlok + 1
			else:
				dlng = dlng + 1

		print( "[I] Download Done" )
		print( "      OK: " + str( dlok ) )
		print( "    Fail: " + str( dlng ) )
		print( "" )
		bDoSomething = True


	if bDoSomething:
		if os.path.isfile( DOWNLOAD_SHEET_BAK ):
			os.remove( DOWNLOAD_SHEET_BAK )
		os.rename( DOWNLOAD_SHEET, DOWNLOAD_SHEET_BAK )

	return True

def ShowUsage():
	program = os.path.basename( sys.argv[0] )
	print( "Usage:" )
	print( "    " + program )
	print( "       " + CaesarCipher( "Wlyuny xiqhfiux mbyyn zil myfywncha uwncihm ni jylzilg", -20 ) )
	print( "")
	print( "    " + program + " -d" )
	print( "       " + CaesarCipher( "Yjrigjvy/yzxmtko wjjfn vxxjmydib oj yjrigjvy nczzo", -21 ) )
	print( "")

if __name__ == '__main__':

	print( "" )
	print( APP_TITLE + " " + APP_VERSION )
	print( "" )

	try:
		AES, RSA = _load_crypto_pycryptodome()
	except:
		print( "[E] Can't load Crypto module! (PyCryptodome not installed?)" )
		sys.exit( 1 )

	if not SystemChecking():
		sys.exit( 1 )

	if not CollectBookInfo():
		sys.exit( 1 )

	if not CheckBookDir():
		sys.exit( 1 )

	if len( sys.argv ) > 1:
		if sys.argv[1] == "-d":
			ProcessDownloadSheet()
		else:
			ShowUsage()
			sys.exit( 1 )

	GenerateDownloadSheet()
