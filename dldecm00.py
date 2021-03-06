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
import time
import zipfile
from zipfile import ZipInfo, ZipFile, ZIP_STORED, ZIP_DEFLATED
import base64
import xml.etree.ElementTree as etree
from contextlib import closing
from clint.textui import progress
from enum import Enum

from caesarcipher import CaesarCipher

SECRET1 = CaesarCipher( "Ernqzbb", -13 )
SECRET2 = CaesarCipher( "ylhktvv", -7 )
SECRET3 = CaesarCipher( "raxtci_xs", -15 )
SECRET4 = CaesarCipher( "lnnpdd_ezvpy", -11 )
SECRET5 = CaesarCipher( "byrhqho_yjuc", -16 )

APP_TITLE = SECRET1 + CaesarCipher( " Huuqy Juctrugjkx & Jkixevzux", -6 )
APP_VERSION = "v1.6"

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
KEY_FILE_NAME_GLOB = CaesarCipher( "fradfwjysm*.dsa", -14 )
KEY_FILE_NAME = CaesarCipher( "zluxzqdsmg", -8 )

EXT_EPUB = ".epub"
EXT_PEM = ".pem"

DOWNLOAD_SHEET = SECRET1 + "Books.txt"
DOWNLOAD_SHEET_BAK = SECRET1 + "Books.bak"
AUTHOR_TITLE_MAP_FILE = "author_title_map.txt"
BOOK_LIST = "booklist.txt"
BOOK_INFO = "bookinfo.txt"

OBFUSCATED_LENGTH_IDPF = 1040
ERROR_LIMITS = 10
MAX_KEY_FILES = 1024
PAUSE_BETWEEN_RETRY = [ 13, 23, 47, 79, 127 ]
RETRY_LIMIT = len( PAUSE_BETWEEN_RETRY )

class EResult( Enum ):
	OKAY = 1
	NO_GOOD = 2
	SKIP = 3

class CBookInfo( object ):
	def __init__( self ):
		self._id = ""
		self._title = ""
		self._author = ""
		self._aeskey = ""

gRsaKeys = []
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
gDbFile = None
gMaxDownload = -1
gGenBooklist = False

gCurBook = CBookInfo()

gDownloadCount = 0


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
			self._rsa = _PKCS1.new( key )
			self._key = key

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

def OpenDb():
	global gDbFile

	try:
		if gDbFile:
			dbFile = gDbFile
		else:
			localAppData = os.getenv( "LOCALAPPDATA" )
			dbFile = os.path.join( localAppData, DB_DIR, DB_FILE_NAME )
		return sqlite3.connect( dbFile )
	except:
		print( "[E] Can't open DB file!" )
		return None

def CollectBookInfo():
	global gAccessToken, gClientId, gRsaKeys, gUserId
	global gArchiveData, gBookData

	conn = OpenDb()
	if conn is None:
		return False

	cursor = conn.execute( CaesarCipher( "COVOMD fkveo PBYW SdowDklvo GROBO uoi='__yk__'", -10 ) )
	data = cursor.fetchone()
	if data is None:
		print( "[E] Can't get data from DB!" )
		return False
	else:
		jsObj = json.loads( data[0].decode( "utf-16-le" ) )
		gAccessToken = jsObj[ SECRET2 ][ SECRET4 ]
		gClientId = jsObj[ SECRET2 ][ SECRET3 ]

	cursor = conn.execute( CaesarCipher( "KWDWUL nsdmw XJGE AlweLstdw OZWJW cwq='jks_hjanslwCwq'", -18 ) )
	data = cursor.fetchone()
	if data is None:
		print( "[E] Can't get data from DB!" )
		return False
	else:
		privateKey = data[0].decode( "utf-16-le" )
		gRsaKeys.append( RSA( privateKey ) )

	cursor = conn.execute( CaesarCipher( "AMTMKB ditcm NZWU QbmuBijtm EPMZM smg='-ve-camzql'", -8 ) )
	data = cursor.fetchone()
	if data is None:
		print( "[E] Can't get data from DB!" )
		return False
	else:
		gUserId = data[0].decode( "utf-16-le" )

	cursor = conn.execute( CaesarCipher( "KWDWUL nsdmw XJGE AlweLstdw OZWJW cwq='-fo-datjsjq'", -18 ) )
	data = cursor.fetchone()
	if data is None:
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

def CollectKeys():
	for kf in glob.glob( os.path.join( gOutDir, KEY_FILE_NAME_GLOB ) ):
		try:
			with open( kf, "rb" ) as f:
				keyBytes = f.read()
			gRsaKeys.append( RSA( keyBytes ) )
			print( "[I] Key loaded from " + kf )
		except:
			continue

	bFound = False
	for idx in range( 1, len( gRsaKeys ) ):
		if gRsaKeys[ idx ]._key == gRsaKeys[ 0 ]._key:
			gRsaKeys.pop( idx )
			bFound = True
			break

	if not bFound:
		fileIdx = 1
		while fileIdx < MAX_KEY_FILES:
			keyFile = os.path.join( gOutDir, KEY_FILE_NAME + "." + str( fileIdx ) + EXT_PEM )
			if not os.path.isfile( keyFile ):
				break

			fileIdx = fileIdx + 1

		if fileIdx >=  MAX_KEY_FILES:
			print( "[W] Too many key files!" )

		with open( keyFile, "wb" ) as f:
			f.write( gRsaKeys[0]._key.exportKey( format='PEM' ) )
		print( "[I] Key file created (" + str( fileIdx ) + ")" )

	print( "[I] Number of key(s) = " + str( len( gRsaKeys ) ) )

	return True

def CheckBookDir():
	if not os.path.isdir( os.path.join( gOutDir, ENC_BOOKS_DIR ) ):
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

def GenerateBooklist():
	booklist = os.path.join( gOutDir, BOOK_LIST )

	count = 0
	try:
		with open( booklist, "w", encoding="utf8" ) as f:
			epubs = glob.glob( os.path.join( gOutDir, DEC_BOOKS_DIR, "*.epub" ) )
			print( "[I] Generating book list. Found " + str( len( epubs ) ) + " ePub files ..." )
			for epub in epubs:
				with closing( ZipFile( open( epub, "rb" ) ) ) as inf:
					opfs = GetOpfNamesFromEpub( inf )
					for fOpf in opfs:
						title, author = GetBookInfo( inf.read( fOpf ) )
						if title != "" or author != "":
							f.write( title + " : " + author + "\n" )
							count = count + 1
							break

			f.write( "\n" )				

	except IOError as e:
		print( "[E] Can't write book list! (" + str( e ) + ")" )
		return False

	print( "[I] Book list generated for " + str( count ) + " books" )

	return True

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
	global gDownloadCount, gMaxDownload

	if not bookId in gBookData.keys():
		print( "[E] You don't have book " + bookId + " !" )
		return EResult.NO_GOOD

	if gMaxDownload > 0 and gDownloadCount >= gMaxDownload:
		return EResult.SKIP

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
		return EResult.NO_GOOD

	if response.status_code == 200:
		# fileSize = os.path.getsize( bookFile )
		# while fileSize < total_length:
		# 	print( "[W] Content-Length = " + str( total_length ) + ", File Size = " + str( fileSize ) )
		# 
		# 	time.sleep( PAUSE_BETWEEN_RETRY )
		# 
		# 	resume_header = { 'Range' : 'bytes=%d-' % fileSize }
		# 	response = requests.get( downloadEpubUrl, headers = resume_header, stream = True, verify=gSslVerify, proxies=gProxy )
		# 
		# 	try:
		# 		with open( bookFile, "ab" ) as f:
		# 			remain_length = int( response.headers.get( "content-length" ) )
		# 			chunk_size = 1024
		# 			expected_size = (remain_length / chunk_size) + 1
		# 			for chunk in progress.bar( response.iter_content( chunk_size = chunk_size ), expected_size = expected_size ):
		# 				if chunk:
		# 					f.write( chunk )
		# 					f.flush()
		# 	except Exception as e:
		# 		print( "[E]   Can't save file! (" + str( e ) + ")" )
		# 		if os.path.isfile( bookFile ):
		# 			os.remove( bookFile )
		# 		return EResult.NO_GOOD
		# 
		# 	fileSize = os.path.getsize( bookFile )

		fileSize = os.path.getsize( bookFile )
		retry = 0
		while fileSize != total_length:
			if retry >= RETRY_LIMIT:
				print( "[E] Can't download book!" )
				if os.path.isfile( bookFile ):
					os.remove( bookFile )
				return EResult.NO_GOOD

			print( "[W] Content-Length = " + str( total_length ) + ", File Size = " + str( fileSize ) )
			os.remove( bookFile )

			time.sleep( PAUSE_BETWEEN_RETRY[ retry ] )
			retry = retry + 1

			response = requests.get( downloadEpubUrl, stream = True, verify=gSslVerify, proxies=gProxy )
			try:
				with open( bookFile, "wb" ) as f:
					total_length_retry = int( response.headers.get( "content-length" ) )
					chunk_size = 1024
					expected_size = (total_length_retry / chunk_size) + 1
					for chunk in progress.bar( response.iter_content( chunk_size = chunk_size ), expected_size = expected_size ):
						if chunk:
							f.write( chunk )
							f.flush()
			except Exception as e:
				print( "[E]   Can't save file! (" + str( e ) + ")" )
				if os.path.isfile( bookFile ):
					os.remove( bookFile )
				return EResult.NO_GOOD

			if response.status_code == 200:
				fileSize = os.path.getsize( bookFile )
			else:
				print( "[E]   Can't download book. [CODE: " + str( response.status_code ) + "]" )
				if os.path.isfile( bookFile ):
					os.remove( bookFile )
				return EResult.NO_GOOD

		gDownloadCount = gDownloadCount + 1
		return EResult.OKAY

	else:
		print( "[E]   Can't download book. [CODE: " + str( response.status_code ) + "]" )
		if os.path.isfile( bookFile ):
			os.remove( bookFile )
		return EResult.NO_GOOD

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
	if elTitle is None:
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
	if elAuthor is None:
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

def GetBookInfo( data ):
	try:
		opf = etree.fromstring( data )
		title = opf.find( 'opf:metadata', NSMAP ).find( 'dc:title', NSMAP ).text
		if title is None:
			title = ""
		author = opf.find( 'opf:metadata', NSMAP ).find( 'dc:creator', NSMAP ).text
		if author is None:
			author = ""
	except:
		pass

	return title, author

def ShowBookInfo( data ):
	global gCurBook

	title, author = GetBookInfo( data )

	gCurBook._title = title
	gCurBook._author = author

	if title != "":
		print( "      Title  : " + title )
	if author != "":
		print( "      Author : " + author )

def SaveBookInfo():
	bookinfo = os.path.join( gOutDir, BOOK_INFO )
	try:
		with open( bookinfo, "a+", encoding="utf8" ) as f:
			f.write( "{0} : {1} : {2} : {3}\n".format( gCurBook._id, gCurBook._aeskey, gCurBook._title, gCurBook._author ) )
		return True
	except Exception as e:
		print( "[W] Can't save book info (" + str( e ) + ")" )
		return False

def DecryptBook( bookId ):
	global gCurBook

	print( "[I] Decrypt  book: " + bookId + " [" +  gBookData[ bookId ][0] + "]" )

	encFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_EPUB )
	decFile = os.path.join( gOutDir, DEC_BOOKS_DIR, bookId + EXT_EPUB )

	if not os.path.isfile( encFile ):
		print( "[E]   File not found: " + encFile )
		return EResult.NO_GOOD

	if not CheckEpubIntegrity( bookId ):
		print( "[E]   Corrupted ePub file! (Re-download)" )
		return EResult.NO_GOOD

	with closing( ZipFile( open( encFile, "rb" ) ) ) as inf:
		namelist = set( inf.namelist() )

		if ENCRYPTION_XML not in namelist:
			print( "[W]   Can't find " + ENCRYPTION_XML + ". Assume it's DRM-free book" )
			if os.path.isfile( decFile ):
				os.remove( decFile )
			shutil.copyfile( encFile, decFile )
			return EResult.OKAY

		for name in META_NAMES:
			namelist.remove(name)

		try:
			# get book AES key from META-INF/encryption.xml
			encryption = etree.fromstring( inf.read( ENCRYPTION_XML ) )
			aesKeyB64 = encryption.findtext( './/enc:CipherValue', None, NSMAP )
			if aesKeyB64 is None:
				print( "[E]   Can't find encrypted AES key!" )
				return EResult.NO_GOOD

			for k in gRsaKeys:
				bookkey = k.decrypt( base64.b64decode( aesKeyB64 ) )
				if bookkey is not None:
					break

			if bookkey is None:
				print( "[E]   Can't decrypt AES key!" )
				return EResult.NO_GOOD

			gCurBook._id = bookId
			gCurBook._aeskey = ''.join( hex( x )[2:].zfill( 2 ) for x in bookkey).upper()

			print( "      AES KEY = {0}".format( gCurBook._aeskey ) )			

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
			return EResult.NO_GOOD

	RenameBook( bookId )
	SaveBookInfo()

	return EResult.OKAY

def RenameBook( bookId ):
	if not bookId in gBookData.keys():
		print( "[E] Can't rename book: wrong book ID " + bookId )
		return False

	decFile = os.path.join( gOutDir, DEC_BOOKS_DIR, bookId + EXT_EPUB )

	if bookId in gTitleMap:
		safeTitle = gTitleMap[ bookId ].replace( "\\", "_" ).replace( "/", "_" ).replace( ":", "_" ).replace( "!?", "" ).replace( "?", "" )
	else:
		safeTitle = gBookData[ bookId ][0].replace( "\\", "_" ).replace( "/", "_" ).replace( ":", "_" ).replace( "!?", "" ).replace( "?", "" )
	titleFile = os.path.join( gOutDir, DEC_BOOKS_DIR, safeTitle + EXT_EPUB )
	if os.path.isfile( titleFile ):
		os.remove( titleFile )
	os.rename( decFile, titleFile )

	print( "[I] Book saved: " + os.path.basename( titleFile ) )

	return True

def GetBook( bookId ):
	result = DownloadBook( bookId )
	if result == EResult.OKAY:
		result = DecryptBook( bookId )

	return result

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
			result = DecryptBook( bookId )
			if result == EResult.OKAY:
				decok = decok + 1
			else:
				decng = decng + 1
				if not gDecryptAll:
					todl.append( bookId )				
			print( "" )

		print( "[I] Decrypt Done" )
		print( "      OK: " + str( decok ) )
		print( "    Fail: " + str( decng ) )
		print( "" )
		if decok > 0:
			bDoSomething = True

	if len( todl ) > 0:
		print( "[I] Books to be downloaded: " + str( len( todl ) ) )
		dlok = 0
		dlng = 0
		dlskip = 0

		bookDir = os.path.join( gOutDir, ENC_BOOKS_DIR )
		if not os.path.isdir( bookDir ):
			try:
				os.makedirs( bookDir )
			except:
				print( "[E] Can't create directory: " + os.path.abspath( bookDir ) )
				result = False

		if result:
			for bookId in todl:
				result = GetBook( bookId )
				if result == EResult.OKAY:
					dlok = dlok + 1
				elif result == EResult.NO_GOOD:
					dlng = dlng + 1
				elif result == EResult.SKIP:
					dlskip = dlskip + 1

				print( "" )
	
			print( "[I] Download Done" )
			print( "      OK: " + str( dlok ) )
			print( "    Fail: " + str( dlng ) )
			print( "    Skip: " + str( dlskip ) )
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
	global gOutDir, gSslVerify, gNeedProcess, gDownloadAll, gDownloadNew, gDecryptAll, gProxy, gMapFile, gDbFile, gMaxDownload, gGenBooklist

	parser = argparse.ArgumentParser()
	parser.add_argument( "-d", "--dldec", action="store_true", help="Download/decrypt books according to download sheet" )
	parser.add_argument( "--dlall", action="store_true", help="Download all books" )
	parser.add_argument( "--dlnew", action="store_true", help="Download books that have not downloaded yet" )
	parser.add_argument( "--decall", action="store_true", help="Decrypt all downloaded books" )
	parser.add_argument( "-o", "--out", help="Output directory", default="." )
	parser.add_argument( "-m", "--map", help="Specify title/author map file" )
	parser.add_argument( "--dbfile", help="Specify database file" )
	parser.add_argument( "--proxy-host", help="Proxy IP address" )
	parser.add_argument( "--proxy-port", help="Proxy port number", type=int )
	parser.add_argument( "--proxy-user", help="Proxy user name" )
	parser.add_argument( "--proxy-password", help="Proxy password" )
	parser.add_argument( "--no-verify", action="store_true", help="Do not verify SSL CA" )
	parser.add_argument( "-n", "--numdl", type=int, help="Max number of downloads" )
	parser.add_argument( "-l", "--list", action="store_true", help="Generate book list" )

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

	if args.dbfile and len( args.dbfile ) > 0:
		gDbFile = args.dbfile

	if args.numdl:
		gMaxDownload = args.numdl

	if args.list:
		gGenBooklist = True

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

	ParseArgument()

	if not CheckBookDir():
		sys.exit( 1 )

	if not CollectKeys():
		sys.exit( 1 )
	
	if gGenBooklist:
		GenerateBooklist()
		sys.exit( 0 )
	elif gNeedProcess:
		ParseAuthorTitleMap( gMapFile )
		ProcessDownloadSheet()

	GenerateDownloadSheet()

