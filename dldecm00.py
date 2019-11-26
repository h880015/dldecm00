#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
dl and dec books
"""

import sys
import os
import re
import shutil
import platform
import argparse
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
APP_VERSION = "v1.1"

MIMETYPE = 'mimetype'
ENCRYPTION_XML = "META-INF/encryption.xml"
CONTAINER_XML = "META-INF/container.xml"
META_NAMES = (MIMETYPE, ENCRYPTION_XML)
NSMAP = {
	'enc' : 'http://www.w3.org/2001/04/xmlenc#',
	'container' : 'urn:oasis:names:tc:opendocument:xmlns:container',
	'opf' : 'http://www.idpf.org/2007/opf',
	'dc' : 'http://purl.org/dc/elements/1.1/'
}

DB_DIR = os.path.join( SECRET1, CaesarCipher( "Uxlju Bcxajpn", -9 )  )
DB_FILE_NAME = "app_" + SECRET2 + "_0." + CaesarCipher( "ruigryzuxgmk", -6 )

DEC_BOOKS_DIR = CaesarCipher( "WirQngwfwd", -5 )
ENC_BOOKS_DIR = os.path.join( DEC_BOOKS_DIR, "enc" )

EXT_EPUB = ".epub"

DOWNLOAD_SHEET = SECRET1 + "Books.txt"
DOWNLOAD_SHEET_BAK = SECRET1 + "Books.bak"
AUTHOR_TITLE_MAP_FILE = "author_title_map.txt"

OBFUSCATED_LENGTH_IDPF = 1040

gRsaKey = None
gUserId = None
gAccessToken = None
gClientId = None
gBookData = dict()
gArchiveData = dict()
gDlBooks = []
gTitleMap = dict()
gAuthorMap = dict()

gNeedProcess = True
gDownloadAll = False
gDownloadNew = False
gDecryptAll = False
gOutDir = "."
gProxy = { 'no': 'pass' }
gSslVerify = True
gMapFile = None

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
	if not os.path.exists( os.path.join( gOutDir, ENC_BOOKS_DIR ) ):
		try:
			os.makedirs( os.path.join( gOutDir, ENC_BOOKS_DIR ) )
		except:
			print( "[E] Can't create directory: " + os.path.abspath( os.path.join( gOutDir, ENC_BOOKS_DIR ) ) )
			return False

		print( "[I] Create directory: " + os.path.abspath( os.path.join( gOutDir, DEC_BOOKS_DIR ) ) )
	
	return True

def GetDlBooks():
	global gDlBooks
	
	for f in glob.glob( os.path.join( gOutDir, ENC_BOOKS_DIR, "*.epub" ) ):
		gDlBooks.append( os.path.splitext( os.path.basename( f ) )[0] )

def DownloadSheetExist():
	return os.path.isfile( os.path.join( gOutDir, DOWNLOAD_SHEET ) )

def GenerateDownloadSheet():
	GetDlBooks()

	dls = os.path.abspath( os.path.join( gOutDir, DOWNLOAD_SHEET ) )

	dled = 0
	total = 0
	archive = 0
	try:
		with open( dls, "w", encoding="utf8" ) as f:
			f.write( "#\n" )
			f.write( "# List of books on " + SECRET1 + "\n" )
			f.write( "#\n" )
			f.write( "# [V] : already downloaded\n" )
			f.write( "# [ ] : not downloaded yet\n" )
			f.write( "# [A] : archive\n" )
			f.write( "#\n" )
			f.write( "# Actions:\n" )
			f.write( "#   [+] : download this book\n" )
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
		print( "[E] Can't write download sheet! (" + str( e ) + ")" )
		return False

	print( "[I] Download sheet file '" + dls + "' generated" )
	print( "      Books      : " + str( total ) )
	print( "      Downloaded : " + str( dled ) )
	print( "      Archive    : " + str( archive ) )

	return True

def DownloadBook( bookId ):
	if not bookId in gBookData.keys():
		print( "[E] You don't have book " + bookId + " !" )
		return False

	print( "[I] Download book: " + bookId + " [" +  gBookData[ bookId ][0] + "]" )
	downloadEpubUrl = "https://api." + SECRET2 + ".com/epub/" + bookId + "?" + SECRET3 + "=" + gClientId + "&" + SECRET4 + "=" + gAccessToken
	response = requests.get( downloadEpubUrl, stream = True, verify=gSslVerify, proxies=gProxy )
	bookFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_EPUB )
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
	except Exception as e:
		print( "[E]   Can't save file! (" + str( e ) + ")" )
		if os.path.isfile( bookFile ):
			os.remove( bookFile )
		return False

	if response.status_code == 200:
		return True
	else:
		print( "[E]   Can't download book. [CODE: " + str( response.status_code ) + "]" )
		if os.path.isfile( bookFile ):
			os.remove( bookFile )
		return False

def EmbeddedFontDeobfuscateIdpf( bookUid, inBuf ):
	from Crypto.Hash import SHA1

	h = SHA1.new()
	h.update( bookUid.encode( "utf-8" ) )
	key = h.digest()

	keyLen = len( key )
	bufLen = len( inBuf )

	processLen = min( bufLen, OBFUSCATED_LENGTH_IDPF )

	keyBytes = key * int( processLen / keyLen )
	remain = processLen % keyLen
	if remain > 0:
		keyBytes = keyBytes + key[ : remain ]

	result = bytes( a ^ b for ( a, b ) in zip( keyBytes, inBuf[ : processLen ] ) )

	if bufLen > processLen:
		result += inBuf[ processLen : ]

	return result

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
		self._encFontIdpf = encFontIdpf= set()
		self._bookUid = ""

		# construct the list of encrypted files
		for elem in encryption.findall( './enc:EncryptedData', NSMAP ):
			path = elem.find( "enc:CipherData", NSMAP ).find( "enc:CipherReference", NSMAP ).get( "URI", None )
			if path is not None:
				path = path.encode('utf-8')
				method = elem.find( "enc:EncryptionMethod", NSMAP ).get( "Algorithm", None )
				if method == "http://www.idpf.org/2008/embedding":
					encFontIdpf.add( path )
				elif method == "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
					encrypted.add( path )
				else:
					print( "[W] Unsupported encrypt algorithm: " + method )
			else:
				print( "[W] Can't find URI!")

		if len(encrypted) != 0:
			print( "      {0} encrypted files".format(len(encrypted)) )
		if len(encFontIdpf) != 0:
			print( "      {0} encrypted Idpf fonts".format(len(encFontIdpf)) )

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
		elif path.encode('utf-8') in self._encFontIdpf:
			if self._bookUid == "":
				print( "[W]   " + path + " not decrypted (no book UID)" )
			else:
				data = EmbeddedFontDeobfuscateIdpf( self._bookUid, data )

		return data

	def SetBookUid( self, bookUid ):
		self._bookUid = bookUid

def GetOpfNamesFromEpub( fEpub ):
	container = etree.fromstring( fEpub.read( CONTAINER_XML ) )
	rootfiles = container.find( "container:rootfiles", NSMAP ).findall( "container:rootfile", NSMAP )

	opfs = []
	for r in rootfiles:
		rf = r.get( "full-path", None )
		if rf is not None:
			opfs.append( rf )

	return opfs

def GetBookUid( decryptor, fEpub ):
	bookUid = ""
	opfs = GetOpfNamesFromEpub( fEpub )
	if len( opfs ) > 0:
		for rf in opfs:
			try:
				opf = etree.fromstring( decryptor.decrypt( rf, fEpub.read( rf ) ) )
				bookUid = bookUid + opf.find( 'opf:metadata', NSMAP ).find( 'dc:identifier', NSMAP ).text + " "
			except Exception as e:
				print( "[E]   Can't get book UID! (" + str( e ) + ")" )
				return
		bookUid = bookUid.strip()
	else:
		print( "[E]   Can't get OPF file name!" )
		return bookUid

	if bookUid != "":
		print( "      Book UID = " + bookUid )
	else:
		print( "[E]   Can't find book UID!" )

	return bookUid

def ChangeTitle( data, newTitle ):
	opf = etree.fromstring( data )
	elTitle = opf.find( 'opf:metadata', NSMAP ).find( 'dc:title', NSMAP )
	if not elTitle:
		print( "[W]   Can't find title in OPF!" )
		return data

	oldTitle = elTitle.text
	if oldTitle == newTitle:
		print( "[N]   New title is the same as title in OPF" )
		return data

	if "\r\n".encode( "utf-8" ) in data:
		lineEnd = "\r\n"
	else:
		lineEnd = "\n"

	lines = data.decode( "utf-8" ).split( lineEnd )

	patTitle = re.compile( "^(.*<dc:title[^>]*>)(.+)(<\/dc:title>.*)$" )
	bFound = False
	for i in range( len( lines ) ):
		l = lines[ i ]
		if "dc:title" in l:
			result = patTitle.match( l )
			if result:
				bFound = True
				oldTitle = result.group( 2 )
				if oldTitle != newTitle:
					lines[ i ] = result.group( 1 ) + newTitle + result.group( 3 )
					print( "      Change title in <dc:title> (" + oldTitle + " -> " + newTitle + ")" )
				else:
					print( "      (<dc:title> is correct, no change)")
				break

	if not bFound:
		print( "[W]   Can't find <dc:title> in OPF!" )
		return data

	idTitle = elTitle.get( "id" )
	if idTitle:
		metas = opf.find( 'opf:metadata', NSMAP ).findall( 'opf:meta[@refines="#' + idTitle + '"]', NSMAP )
		if metas and metas[0].text != newTitle:
			patTitle2 = re.compile( '^(.*<meta refines="#' + idTitle + '"[^>]*>)(.+)(<\/meta>.*)$' )
			bFound = False
			for i in range( len( lines ) ):
				l = lines[ i ]
				if ('refines="#' + idTitle) in l:
					result2 = patTitle2.match( l )
					if result2:
						bFound = True
						oldTitle = result2.group( 2 )
						if oldTitle != newTitle:
							lines[ i ] = result2.group( 1 ) + newTitle + result2.group( 3 )
							print( "      Change title in <meta refines> (" + oldTitle + " -> " + newTitle + ")" )
						else:
							print( "      (<meta refines> author is correct, no change)")
						break

			if not bFound:
				print( "[W]   Can't change <meta refines> title in OPF!" )

	data = lineEnd.join( lines ).encode( "utf-8" )

	return data

def ChangeAuthor( data, newAuthor ):
	opf = etree.fromstring( data )
	elAuthor = opf.find( 'opf:metadata', NSMAP ).find( 'dc:creator', NSMAP )
	if not elAuthor:
		print( "[W]   Can't find author in OPF!" )
		return data

	oldAuthor = elAuthor.text
	if oldAuthor == newAuthor:
		print( "[N]   New author is the same as author in OPF" )
		return data

	if "\r\n".encode( "utf-8" ) in data:
		lineEnd = "\r\n"
	else:
		lineEnd = "\n"

	lines = data.decode( "utf-8" ).split( lineEnd )

	patAuthor = re.compile( "^(.*<dc:creator[^>]*>)(.+)(<\/dc:creator>.*)$" )
	bFound = False
	for i in range( len( lines ) ):
		l = lines[ i ]
		if "dc:creator" in l:
			result = patAuthor.match( l )
			if result:
				bFound = True
				oldAuthor = result.group( 2 )
				if oldAuthor != newAuthor:
					lines[ i ] = result.group( 1 ) + newAuthor + result.group( 3 )
					print( "      Change author in <dc:creator> (" + oldAuthor + " -> " + newAuthor + ")" )
				else:
					print( "      (<dc:creator> is correct, no change)" )
				break

	if not bFound:
		print( "[W]   Can't find <dc:creator> in OPF!" )
		return data

	idAuthor = elAuthor.get( "id" )
	if idAuthor:
		metas = opf.find( 'opf:metadata', NSMAP ).findall( 'opf:meta[@refines="#' + idAuthor + '"][@property="file-as"]', NSMAP )
		if metas and metas[0].text != newAuthor:
			patAuthor2 = re.compile( '^(.*<meta refines="#' + idAuthor + '"[^>]*>)(.+)(<\/meta>.*)$' )
			bFound = False
			for i in range( len( lines ) ):
				l = lines[ i ]
				if ('refines="#' + idAuthor) in l and 'property="file-as"' in l:
					result2 = patAuthor2.match( l )
					if result2:
						bFound = True
						oldAuthor = result2.group( 2 )
						if oldAuthor != newAuthor:
							lines[ i ] = result2.group( 1 ) + newAuthor + result2.group( 3 )
							print( "      Change author in <meta refines> (" + oldAuthor + " -> " + newAuthor + ")" )
						else:
							print( "      (<meta refines> author is correct, no change)" )
						break

			if not bFound:
				print( "[W]   Can't find <meta refines> author in OPF!" )

	data = lineEnd.join( lines ).encode( "utf-8" )

	return data

def ShowBookInfo( data ):
	try:
		opf = etree.fromstring( data )
		title = opf.find( 'opf:metadata', NSMAP ).find( 'dc:title', NSMAP ).text
		author = opf.find( 'opf:metadata', NSMAP ).find( 'dc:creator', NSMAP ).text
		if title is not None and title != "":
			print( "      Title  : " + title )
		if author is not None and author != "":
			print( "      Author : " + author )
	except:
		pass

def DecryptBook( bookId ):
	print( "[I] Decrypt  book: " + bookId + " [" +  gBookData[ bookId ][0] + "]" )

	encFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_EPUB )
	decFile = os.path.join( gOutDir, DEC_BOOKS_DIR, bookId + EXT_EPUB )

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
			aesKeyB64 = encryption.findtext( './/enc:CipherValue', None, NSMAP )
			if aesKeyB64 is None:
				print( "[E]   Can't find encrypted AES key!" )
				return False

			bookkey = gRsaKey.decrypt( base64.b64decode( aesKeyB64 ) )
			if bookkey is None:
				print( "[E]   Can't decrypt AES key!" )
				return False

			print( "      AES KEY = {0}".format( ''.join( hex( x )[2:].zfill( 2 ) for x in bookkey).upper() ) )

			decryptor = Decryptor( bookkey, encryption )
			if len( decryptor._encFontIdpf ) > 0:
				decryptor.SetBookUid( GetBookUid( decryptor, inf ) )
			opfs = GetOpfNamesFromEpub( inf )
			if len( opfs ) > 1:
				print( "[W]   Num of rootfile = " + str( len( opfs ) ) )
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
					data = decryptor.decrypt( path, data )
					if path in opfs:
						if bookId in gTitleMap:
							data = ChangeTitle( data, gTitleMap[ bookId ] )
						if bookId in gAuthorMap:
							data = ChangeAuthor( data, gAuthorMap[ bookId ] )
						ShowBookInfo( data )
					outf.writestr( zi, data )
		except Exception as e:
			print( "[E]   Can't decrypt book! (" + str( e ) + ")" )
			if os.path.isfile( decFile ):
				os.remove( decFile )
			return False

	RenameBook( bookId )

	return True

def RenameBook( bookId ):
	if not bookId in gBookData.keys():
		print( "[E] Can't rename book: wrong book ID " + bookId )
		return False

	decFile = os.path.join( gOutDir, DEC_BOOKS_DIR, bookId + EXT_EPUB )
	
	if bookId in gTitleMap:
		titleFile = os.path.join( gOutDir, DEC_BOOKS_DIR, gTitleMap[ bookId ] + EXT_EPUB )
	else:
		titleFile = os.path.join( gOutDir, DEC_BOOKS_DIR, gBookData[ bookId ][0] + EXT_EPUB )
	if os.path.isfile( titleFile ):
		os.remove( titleFile )
	os.rename( decFile, titleFile )

	print( "[I] Book saved: " + gBookData[ bookId ][0] + EXT_EPUB )

	return True

def GetBook( bookId ):
	if DownloadBook( bookId ):
		if DecryptBook( bookId ):
			return True

	return False

def CheckEpubIntegrity( bookId ):
	bookFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_EPUB )
	
	try:
		zf = zipfile.ZipFile( bookFile )
		ret = zf.testzip()
		if ret is None:
			return True
		else:
			return False
	except:
		return False

def DeleteBook( bookId ):
	if not bookId in gBookData.keys():
		print( "[E] Can't delete book: wrong book ID " + bookId )
		return False

	print( "      Delete book: " + bookId )

	result = True
	bookFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_EPUB )
	decFile = os.path.join( gOutDir, DEC_BOOKS_DIR, bookId + EXT_EPUB )
	titleFile = os.path.join( gOutDir, DEC_BOOKS_DIR, gBookData[ bookId ][0] + EXT_EPUB )

	try:
		if os.path.isfile( bookFile ):
			os.remove( bookFile )
	except:
		result = False
	try:
		if os.path.isfile( decFile ):
			os.remove( decFile )
	except:
		result = False
	try:
		if os.path.isfile( titleFile ):
			os.remove( titleFile )
	except:
		result = False

	return result

def ProcessDownloadSheet():
	if not DownloadSheetExist():
		print( "[E] Download sheet not exist!" )
		return False

	dls = os.path.abspath( os.path.join( gOutDir, DOWNLOAD_SHEET ) )

	print( "[I] Parse download sheet" )
	todl = []
	torm = []
	todec = []
	try:
		for line in open( dls, "r", encoding="utf8" ):
			if line.startswith( "[" ):
				mark = line[1].upper()
				id = line[4:19]
				if mark == "-":
					torm.append( id )
				elif mark == "D" or (gDecryptAll and mark == "V"):
					todec.append( id )
				elif mark == " " and gDownloadNew:
					todl.append( id )
				elif mark == "+" or (gDownloadAll and mark != "A"):
					todl.append( id )

	except IOError as e:
		print( "[E] Can't read download sheet! (" + str( e ) + ")" )
		return False

	result = True
	bDoSomething = False

	if len( torm ) > 0:
		print( "[I] Books to be delete: " + str( len( torm ) ) )
		for bookId in torm:
			DeleteBook( bookId )

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
			print( "" )

		print( "[I] Decrypt Done" )
		print( "      OK: " + str( decok ) )
		print( "    Fail: " + str( decng ) )
		print( "" )
		bDoSomething = True

	if len( todl ) > 0:
		print( "[I] Books to be downloaded: " + str( len( todl ) ) )
		dlok = 0
		dlng = 0

		bookDir = os.path.join( gOutDir, ENC_BOOKS_DIR )
		if not os.path.exists( bookDir ):
			try:
				os.makedirs( bookDir )
			except:
				print( "[E] Can't create directory: " + os.path.abspath( bookDir ) )
				result = False

		if result:
			for bookId in todl:
				if GetBook( bookId ):
					dlok = dlok + 1
				else:
					dlng = dlng + 1
				print( "" )
	
			print( "[I] Download Done" )
			print( "      OK: " + str( dlok ) )
			print( "    Fail: " + str( dlng ) )
			print( "" )
			if dlok > 0:
				bDoSomething = True

	if bDoSomething:
		if os.path.isfile( os.path.join( gOutDir, DOWNLOAD_SHEET_BAK ) ):
			os.remove( os.path.join( gOutDir, DOWNLOAD_SHEET_BAK ) )
		os.rename( os.path.join( gOutDir, DOWNLOAD_SHEET ), os.path.join( gOutDir, DOWNLOAD_SHEET_BAK ) )

	return result

def ParseAuthorTitleMap( mapFile ):
	global gAuthorMap, gTitleMap
	
	try:
		lines = list( open( mapFile, encoding = "utf-8" ) )
		pat = re.compile( "^(\w) (\w+) : (.+)$" )
		for l in lines:
			if l.startswith( "A" ):
				result = pat.match( l )
				if result:
					bookId = result.group( 2 )
					author = result.group( 3 )
					gAuthorMap.update( { bookId : author } )
			elif l.startswith( "T" ):
				result = pat.match( l )
				if result:
					bookId = result.group( 2 )
					title = result.group( 3 )
					gTitleMap.update( { bookId : title } )
	except:
		pass

	if len( gAuthorMap ) > 0 or len( gTitleMap ) > 0:
		print( "[I] Load " + str( len( gAuthorMap ) ) + " author and " + str( len( gTitleMap ) ) + " title from " + mapFile )

def ParseArgument():
	global gOutDir, gSslVerify, gNeedProcess, gDownloadAll, gDownloadNew, gDecryptAll, gProxy, gMapFile

	parser = argparse.ArgumentParser()
	parser.add_argument( "-d", "--dldec", action="store_true", help="Download/decrypt books according to download sheet" )
	parser.add_argument( "--dlall", action="store_true", help="Download all books" )
	parser.add_argument( "--dlnew", action="store_true", help="Download books that have not downloaded yet" )
	parser.add_argument( "--decall", action="store_true", help="Decrypt all downloaded books" )
	parser.add_argument( "-o", "--out", help="Output directory", default="." )
	parser.add_argument( "-m", "--map", help="Specify title/author map file" )
	parser.add_argument( "--proxy-host", help="Proxy IP address" )
	parser.add_argument( "--proxy-port", help="Proxy port number", type=int )
	parser.add_argument( "--proxy-user", help="Proxy user name" )
	parser.add_argument( "--proxy-password", help="Proxy password" )
	parser.add_argument( "--no-verify", action="store_true", help="Do not verify SSL CA" )

	args = parser.parse_args()
	gOutDir = args.out

	if args.no_verify:
		gSslVerify = False

	if args.dlall:
		gDownloadAll = True
	elif args.dlnew:
		gDownloadNew = True
	elif args.decall:
		gDecryptAll = True
	elif not args.dldec:
		gNeedProcess = False

	if args.proxy_host and args.proxy_port:
		proxy = args.proxy_host + ":" + str( args.proxy_port )
		if args.proxy_user and args.proxy_password:
			auth = args.proxy_user + ":" + args.proxy_password
			gProxy = {
				'http'  : 'http://' + auth + "@" + proxy,
				'https' : 'https://' + auth + "@" + proxy
			}
		else:
			gProxy = {
				'http'  : 'http://' + proxy,
				'https' : 'https://' + proxy
			}

	if args.map and len( args.map ) > 0:
		gMapFile = args.map

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

	ParseArgument()

	if gNeedProcess:
		ParseAuthorTitleMap( gMapFile )
		ProcessDownloadSheet()

	GenerateDownloadSheet()
