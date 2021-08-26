#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
dl and dec books V2 for new Windows Desktop App
"""

import sys
import os
import re
import shutil
import platform
import argparse
import json
import glob
import requests
import zlib
from zipfile import ZipInfo, ZipFile, ZIP_STORED, ZIP_DEFLATED
import base64
import xml.etree.ElementTree as etree
from contextlib import closing
from clint.textui import progress
from tqdm import tqdm
from enum import Enum
import traceback
import hashlib
from datetime import datetime
from datetime import timedelta
import time

from dumpleveldb import ParseLdbDir
from caesarcipher import CaesarCipher

SECRET1 = base64.b64decode( CaesarCipher( 'BtCoGN1cid==', -7 ) ).decode( 'utf-8' )
SECRET2 = base64.b64decode( CaesarCipher( 'rYI0tYD6Cp9ytXbltdMyQX1msp5as20mt3ImtdLmuaDmsNLmsXcztdWpvM9guXMktq9nPNucN2EmuN50OK0oDURn', -17 ) ).decode( 'utf-8' )
SECRET3 = base64.b64decode( CaesarCipher( "PhQcUB1qw+zxd+vwpV==", -21 ) ).decode( 'utf-8' )
SECRET4 = base64.b64decode( CaesarCipher( 'BO9rGEeoC3ZdkuNvHY==', -8 ) ).decode( 'utf-8' )
SECRET5 = base64.b64decode( CaesarCipher( 'FvGMCQ9FE0eQEr==', -11 ) ).decode( 'utf-8' )
SECRET6 = base64.b64decode( CaesarCipher( 'GJ96nJkfLF81YwNtXR1uL2yhqT9mnQftFJ50MJjtGJSwVR9GVSttZGOsZGIsZvxtDKOjoTIKMJWYnKDiAGZ3YwZ2VPuYFSEAGPjtoTyeMFOUMJAeolxtD2ulo21yYmtmYwNhAQRjZl4kZGLtH2SzLKWcYmHmAl4mAt==', -13 ) ).decode( 'utf-8' )
SECRET7 = base64.b64decode( CaesarCipher( 'JfOavfOrBT==', -19 ) ).decode( 'utf-8' )
SECRET8 = base64.b64decode( CaesarCipher( 'U1k5Ly84dV5YcmZoTyb3UZ==', -25 ) )
SECRET9 = base64.b64decode( CaesarCipher( 'U29qVihjHilvx24=', -22 ) ).decode( 'utf-8' )
SECRET10 = base64.b64decode( CaesarCipher( 'BGMBCPQFBB==', -11 ) ).decode( 'utf-8' )
SECRET11 = base64.b64decode( CaesarCipher( 'rLBzqw1vN2JirO==', -14 ) ).decode( 'utf-8' )
SECRET12 = base64.b64decode( CaesarCipher( 'EDB0gM9egDvnjMrbhm==', -6 ) ).decode( 'utf-8' )
SECRET13 = base64.b64decode( CaesarCipher( 'sZJ0uZE6Dq9zuYcmueNzRY1ntq5bt20nu3JnueMnvbEntOMntYdaueXqwN9hvYNlur9esOp0RPAdFMBlt2JhReddRX9rsO5bRKM1JV0=', -18 ) ).decode( 'utf-8' )
SECRET14 = base64.b64decode( CaesarCipher( 'AeSyQ2LcELAas3MluTL1IU0oDURn', -17 ) ).decode( 'utf-8' )
SECRET15 = base64.b64decode( CaesarCipher( 'oTVbpyR0LGfxqC==', -12 ) ).decode( 'utf-8' )

DEBUG_MODE = False
USE_TQDM = False

APP_TITLE = SECRET1 + " Books Downloader & Decryptor"
APP_VERSION = "v2.3"

MIMETYPE = 'mimetype'
ENCRYPTION_XML = "META-INF/encryption.xml"
CONTAINER_XML = "META-INF/container.xml"
META_NAMES = (MIMETYPE, ENCRYPTION_XML)
NSMAP = {
	'enc' : 'http://www.w3.org/2001/04/xmlenc#',
	'comp' : 'http://www.idpf.org/2016/encryption#compression',
	'container' : 'urn:oasis:names:tc:opendocument:xmlns:container',
	'opf' : 'http://www.idpf.org/2007/opf',
	'dc' : 'http://purl.org/dc/elements/1.1/'
}

DEC_BOOKS_DIR = "RdmLibraryV2"
ENC_BOOKS_DIR = os.path.join( DEC_BOOKS_DIR, "enc" )
KEY_FILE_NAME = "rdmprivkeyv2"
KEY_FILE_NAME_GLOB = KEY_FILE_NAME + "*.pem"
TOKEN_FILE_NAME = "rdmtoken.txt"
LIBRARY_ITEMS_FILE_NAME = "rdmlibitems"

EXT_EPUB = ".epub"
EXT_PEM = ".pem"
EXT_LCPL = ".lcpl"
EXT_JSON = ".json"
GLOB_EPUB = "*" + EXT_EPUB

DOWNLOAD_SHEET = SECRET1 + "BooksV2.txt"
DOWNLOAD_SHEET_BAK = SECRET1 + "BooksV2.bak"
AUTHOR_TITLE_MAP_FILE = "author_title_map.txt"
BOOK_LIST_DEC = "booklistv2.txt"
BOOK_LIST_RAW = "booklistrawv2.txt"
BOOK_INFO = "bookinfov2.txt"

OBFUSCATED_LENGTH_IDPF = 1040
ERROR_LIMITS = 10
MAX_KEY_FILES = 1024
PAUSE_BETWEEN_RETRY = [ 13, 23, 47, 79, 127 ]
RETRY_LIMIT = len( PAUSE_BETWEEN_RETRY )

REDOWNLOAD_LIBITEM_DAYS = 7

LIBITEM_IDX_RID = 0
LIBITEM_IDX_TITLE = 1
LIBITEM_IDX_AUTHOR = 2
LIBITEM_IDX_LICENSE = 3
LIBITEM_IDX_ARCHIVED = 4

class EResult( Enum ):
	OKAY = 1
	NO_GOOD = 2
	SKIP = 3
	RETRY = 4

class CBookInfo( object ):
	def __init__( self ):
		self._id = ""
		self._title = ""
		self._author = ""
		self._aeskey = ""

gRsaKeys = []
gAccessToken = None
gDlBooks = []
gTitleMap = dict()
gAuthorMap = dict()

gLicUrlMap = dict()
gLibraryItems = dict()
gBookIdMap = dict()
gHttpHeader = dict()

gNeedProcess = True
gDownloadAll = False
gDownloadNew = False
gDecryptAll = False
gOutDir = "."
gProxy = { 'no': 'pass' }
gSslVerify = True
gMapFile = None
gMaxDownload = -1
gGenBooklistDec = False
gGenBooklistRaw = False
gDecOverwrite = True
gRedlLibitems = False

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

def CollectKeys():
	for kf in glob.glob( os.path.join( gOutDir, KEY_FILE_NAME_GLOB ) ):
		try:
			with open( kf, "rb" ) as f:
				keyBytes = f.read()
			gRsaKeys.append( RSA( keyBytes ) )
			print( "[I] Key loaded from " + kf )
		except:
			print( "[W] Can't load key from file: " + kf )
			continue

	pkey = RetrievePrivateKey()
	bFound = False
	if pkey is not None:
		print( '[I] Key retrieved from system' )
		rsaKey = RSA( pkey )
		for k in gRsaKeys:
			if rsaKey._key == k._key:
				bFound = True
				break

		if not bFound:
			gRsaKeys.append( rsaKey )
			fileIdx = 1
			while fileIdx < MAX_KEY_FILES:
				keyFile = os.path.join( gOutDir, KEY_FILE_NAME + "." + str( fileIdx ) + EXT_PEM )
				if not os.path.exists( keyFile ):
					break

				fileIdx = fileIdx + 1

			if fileIdx >=  MAX_KEY_FILES:
				print( "[W] Too many key files!" )

			with open( keyFile, "wb" ) as f:
				f.write( rsaKey._key.exportKey( format='PEM' ) )
			print( "[I] Key file created (" + str( fileIdx ) + ")" )

	if len( gRsaKeys ) == 0:
		print( "[E] Can't find any key!" )
		return False
	else:
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
	
	for f in glob.glob( os.path.join( gOutDir, ENC_BOOKS_DIR, GLOB_EPUB ) ):
		gDlBooks.append( os.path.splitext( os.path.basename( f ) )[0] )

def DownloadSheetExist():
	return os.path.isfile( os.path.join( gOutDir, DOWNLOAD_SHEET ) )

def GenerateDecBooklist():
	return GenerateBooklist( os.path.join( gOutDir, DEC_BOOKS_DIR, GLOB_EPUB ), BOOK_LIST_DEC )

def GenerateRawBooklist():
	return GenerateBooklist( os.path.join( gOutDir, ENC_BOOKS_DIR, GLOB_EPUB ), BOOK_LIST_RAW )

def GenerateBooklist( bookDir, fList ):
	booklist = os.path.join( gOutDir, fList )

	count = 0
	try:
		with open( booklist, "w", encoding="utf-8" ) as f:
			epubs = glob.glob( bookDir )
			print( "[I] Generating book list. Found " + str( len( epubs ) ) + " ePub files ..." )
			for epub in epubs:
				with closing( ZipFile( open( epub, "rb" ) ) ) as inf:
					opfs = GetOpfNamesFromEpub( inf )
					bFound = False
					for fOpf in opfs:
						title, author = GetBookInfo( inf.read( fOpf ) )
						if title is not None and author is not None:
							f.write( title + " : " + author + "\n" )
							count = count + 1
							bFound = True
							break

					if not bFound:
						print( "[W] Can't find title/author for " + os.path.basename( epub ) )

			f.write( "\n" )				

	except IOError as e:
		print( "[E] Can't write book list! (" + str( e ) + ")" )
		return False

	print( "[I] Book list saved to file: " + booklist + " [" + str( count ) + " books]" )

	return True

def GenerateDownloadSheet():
	GetDlBooks()

	dls = os.path.abspath( os.path.join( gOutDir, DOWNLOAD_SHEET ) )

	dled = 0
	total = 0
	archive = 0
	try:
		with open( dls, "w", encoding="utf-8" ) as f:
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

			for k in gLibraryItems.keys():
				if not gLibraryItems[ k ][ LIBITEM_IDX_ARCHIVED ]:
					total = total + 1
					if k in gDlBooks:
						line = "[V] "
						dled = dled + 1
					else:
						line = "[ ] "
					line = line + "{:15s} {:s}\n".format( k, gLibraryItems[ k ][ LIBITEM_IDX_TITLE ] )
					f.write( line )

			f.write( "\n" )

			for k in gLibraryItems.keys():
				if gLibraryItems[ k ][ LIBITEM_IDX_ARCHIVED ]:
					archive = archive + 1
					if k in gDlBooks:
						line = "[O] "
						dled = dled + 1
					else:
						line = "[A] "
					line = line + "{:15s} {:s}\n".format( k, gLibraryItems[ k ][ LIBITEM_IDX_TITLE ] )
					f.write( line )

	except IOError as e:
		print( "[E] Can't write download sheet! (" + str( e ) + ")" )
		return False

	print( "[I] Download sheet file " + dls + " generated" )
	print( "      Books      : " + str( total ) )
	print( "      Downloaded : " + str( dled ) )
	print( "      Archive    : " + str( archive ) )

	return True

def SaveDlEpub( epubUrl, bookFile ):
	global gDownloadCount

	response = requests.get( epubUrl, stream = True, verify=gSslVerify, proxies=gProxy, headers=gHttpHeader )
	try:
		with open( bookFile, "wb" ) as f:
			total_length = int( response.headers.get( "content-length" ) )
			chunk_size = 1024
			expected_size = (total_length / chunk_size) + 1
			if USE_TQDM:
				pbar = tqdm( total=total_length, initial=0, unit='B', unit_scale=True, unit_divisor=chunk_size, ncols=78, ascii=True ) # , desc=bookId
				for chunk in response.iter_content( chunk_size = chunk_size ):
					if chunk:
						f.write( chunk )
						f.flush()
						pbar.update( chunk_size )
				pbar.close()
			else:
				for chunk in progress.bar( response.iter_content( chunk_size = chunk_size ), expected_size = expected_size ):
					if chunk:
						f.write( chunk )
						f.flush()
	except Exception as e:
		print( "[E]   Can't save file " + bookFile + "! (" + str( e ) + ")" )
		return EResult.NO_GOOD

	if response.status_code == 200:
		fileSize = os.path.getsize( bookFile )
		if fileSize == total_length:
			gDownloadCount = gDownloadCount + 1
			return EResult.OKAY
		else:
			print( "[W]   Content-Length (" + str( total_length ) + ") != File Size (" + str( fileSize ) + ")" )
			return EResult.RETRY
	else:
		print( "[E]   Can't download book. [CODE: " + str( status_code ) + "]" )
		return EResult.NO_GOOD

def DownloadBook( bookId ):

	if not bookId in gLibraryItems.keys():
		print( "[E] You don't have book " + bookId + " !" )
		return EResult.NO_GOOD

	if gMaxDownload > 0 and gDownloadCount >= gMaxDownload:
		return EResult.SKIP

	print( "[I] Download book: " + bookId + " [" +  gLibraryItems[ bookId ][ LIBITEM_IDX_TITLE ] + "]" )

	lcplFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_LCPL )
	urlLic = gLibraryItems[ bookId ][ LIBITEM_IDX_LICENSE ]

	try:
		response = requests.get( urlLic, verify=gSslVerify, proxies=gProxy, headers=gHttpHeader )
	except Exception as e:
		print( "[E]   Can't download LCPL file! (" + str( e ) + ")" )
		return EResult.NO_GOOD

	if response.status_code == 200:
		with open( lcplFile, "w", encoding = "utf-8" ) as f:
			f.writelines( response.text )
	else:
		print( "[E]   Can't download LCPL file! [CODE: " + str( response.status_code ) + "]" )
		return EResult.NO_GOOD

	try:
		jsonLcpl = response.json()
	except Exception as e:
		print( "[E]   Can't parse LCPL file! (" + str( e ) + ")" )
		return EResult.NO_GOOD

	epubUrl = ""
	for item in jsonLcpl['links']:
		if item['rel'] == 'publication':
			epubUrl = item['href']
	if epubUrl == "":
		print( "[E]   Can't find publication URL for book!" )
		return EResult.NO_GOOD

	bookFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_EPUB )
	if os.path.isfile( bookFile ):
		print( "[N]   Overwrite existing ePub file" )

	retry = 0
	while retry < RETRY_LIMIT:
		ret = SaveDlEpub( epubUrl, bookFile )
		if ret != EResult.RETRY:
			return ret
		retry = retry + 1

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

	def __init__(self, bookkey, encryption, isLcp):
		"""
		Parameters:
			bookkey(str) : AES key for decrypting book content
			encryption(Element) : content of the file META-INF/encryption.xml
			isLcp(boolean) : is LCP encrypted epub
		"""
		self._bookkey = bookkey

		self._lcpenc = lcpenc = set()
		self._deflated = deflated = set()
		self._originalLen = originalLen = dict()
		self._encrypted = encrypted = set()
		self._encFontIdpf = encFontIdpf= set()
		self._bookUid = ""

		# construct the list of encrypted files
		for elem in encryption.findall( './enc:EncryptedData', NSMAP ):
			path = elem.find( "enc:CipherData", NSMAP ).find( "enc:CipherReference", NSMAP ).get( "URI", None )
			if path is not None:
				path = path.encode('utf-8')
				method = elem.find( "enc:EncryptionMethod", NSMAP ).get( "Algorithm", None )
				if isLcp:
					if method == "http://www.idpf.org/2008/embedding":
						encFontIdpf.add( path )
					elif method == "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
						lcpenc.add( path )
						compression = elem.find( "enc:EncryptionProperties", NSMAP ).find( "enc:EncryptionProperty", NSMAP ).find( "comp:Compression", NSMAP ).get( "Method", None )
						if compression is not None:
							if compression == "8":
								deflated.add( path )
							elif compression != "0":
								print( "[W] Unsupported compression (" + compression + ") for file " + path )
						else:
							print( "[W] Can't find Compression for " + path )
						origLen =elem.find( "enc:EncryptionProperties", NSMAP ).find( "enc:EncryptionProperty", NSMAP ).find( "comp:Compression", NSMAP ).get( "OriginalLength", None )
						if origLen is not None:
							originalLen[ path ] = int( origLen )
						else:
							print( "[W] Can't find OriginalLength for " + path )
					else:
						print( "[W] Unsupported encrypt algorithm (" + method + ") for file " + path.decode() )
				else:
					if method == "http://www.idpf.org/2008/embedding":
						encFontIdpf.add( path )
					elif method == "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
						encrypted.add( path )
					else:
						print( "[W] Unsupported encrypt algorithm (" + method + ") for file " + path.decode() )
			else:
				print( "[W] Can't find URI!")

		if len( lcpenc ) != 0:
			print( "      {0} LCP encrypted files".format(len(lcpenc)) )			
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
		path = path.encode( 'utf-8' )
		if path in self._lcpenc:
			data = AES(self._bookkey, data[0:16]).decrypt(data[16:])
			if path in self._deflated:
				data = zlib.decompress( data, -15 )
			else:
				numPadding = data[-1]
				if (numPadding > 0) and (numPadding <= 16):
					data = data[ : numPadding * -1]
			if path in self._originalLen:
				if len( data ) != self._originalLen[ path ]:
					print( "[W]   " + path.decode() + " Original Length = " + str( self._originalLen[ path ] ) + ", Data Length = " + str( len( data ) ) )
		elif path in self._encrypted:
			data = AES(self._bookkey, data[0:16]).decrypt(data[16:])
			numPadding = data[-1]
			if (numPadding > 0) and (numPadding <= 16):
				data = data[ : numPadding * -1]
		elif path in self._encFontIdpf:
			if self._bookUid == "":
				print( "[W]   " + path.decode() + " not decrypted (no book UID)" )
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

def GetBookInfo( data ):
	title = None
	author = None
	try:
		opf = etree.fromstring( data )
		title = opf.find( 'opf:metadata', NSMAP ).find( 'dc:title', NSMAP ).text
		author = opf.find( 'opf:metadata', NSMAP ).find( 'dc:creator', NSMAP ).text
	except:
		pass

	return title, author

def ShowBookInfo( data ):
	global gCurBook

	title, author = GetBookInfo( data )

	if title is not None and title != "":
		print( "      Title  : " + title )
	if author is not None and author != "":
		print( "      Author : " + author )

	if title is None:
		title = "<None>"
	if author is None:
		author = "<None>"

	gCurBook._title = title
	gCurBook._author = author

def SaveBookInfo():
	bookinfo = os.path.join( gOutDir, BOOK_INFO )
	try:
		with open( bookinfo, "a+", encoding="utf-8" ) as f:
			f.write( "{0} : {1} : {2} : {3}\n".format( gCurBook._id, gCurBook._aeskey, gCurBook._title, gCurBook._author ) )
		return True
	except Exception as e:
		print( "[W] Can't save book info (" + str( e ) + ")" )
		return False

def DecryptBook( bookId ):
	global gCurBook

	print( "[I] Decrypt book: " + bookId + " [" +  gLibraryItems[ bookId ][ LIBITEM_IDX_TITLE ] + "]" )

	encFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_EPUB )
	lcplFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_LCPL )
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
			encryption = etree.fromstring( inf.read( ENCRYPTION_XML ) )
			if os.path.isfile( lcplFile ):
				# use LCPL if [bookid].lcpl exist
				try:
					with open( lcplFile, "r", encoding="utf-8" ) as f:
						jsonLcpl = json.load( f )
				except Exception as e:
					print( "[E]   Can't parse LCPL file! (" + str( e ) + ")" )
					return EResult.NO_GOOD
				try:
					aesKeyB64 = jsonLcpl['encryption']['content_key']['encrypted_value']
				except:
					print( "[E]   Can't find content key in LCPL file!" )
					return EResult.NO_GOOD

				isLcp = True
				for k in gRsaKeys:
					bookkey = k.decrypt( base64.b64decode( aesKeyB64 ) )
					if bookkey is not None:
						break
			else:
				# get book AES key from META-INF/encryption.xml
				aesKeyB64 = encryption.findtext( './/enc:CipherValue', None, NSMAP )
				if aesKeyB64 is None:
					print( "[E]   Can't find encrypted AES key!" )
					return EResult.NO_GOOD
	
				isLcp = False
				for k in gRsaKeys:
					bookkey = k.decrypt( base64.b64decode( aesKeyB64 ) )
					if bookkey is not None:
						break

			if bookkey is None:
				print( "[E]   Can't decrypt AES key!" )
				return EResult.NO_GOOD

			gCurBook._id = bookId
			gCurBook._aeskey = ''.join( hex( x )[2:].zfill( 2 ) for x in bookkey).upper()

			print( "      KEY = {0}".format( gCurBook._aeskey ) )

			decryptor = Decryptor( bookkey, encryption, isLcp )
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
			if DEBUG_MODE:
				traceback.print_exc()

			if os.path.isfile( decFile ):
				os.remove( decFile )
			return EResult.NO_GOOD

	RenameBook( bookId )
	SaveBookInfo()

	return EResult.OKAY

def RenameBook( bookId ):
	if not bookId in gLibraryItems.keys():
		print( "[E] Can't rename book: wrong book ID " + bookId )
		return False

	decFile = os.path.join( gOutDir, DEC_BOOKS_DIR, bookId + EXT_EPUB )

	if bookId in gTitleMap:
		safeTitle = gTitleMap[ bookId ].replace( "\\", "_" ).replace( "/", "_" ).replace( ":", "_" ).replace( "!?", "" ).replace( "?", "" )
	else:
		safeTitle = gLibraryItems[ bookId ][ LIBITEM_IDX_TITLE ].replace( "\\", "_" ).replace( "/", "_" ).replace( ":", "_" ).replace( "!?", "" ).replace( "?", "" )
	titleFile = os.path.join( gOutDir, DEC_BOOKS_DIR, safeTitle + EXT_EPUB )
	if gDecOverwrite:
		try:
			if os.path.exists( titleFile ):
				os.remove( titleFile )
		except:
			print( "[E] Can't delete file: " + titleFile )
			return False
	else:
		i = 0
		while os.path.exists( titleFile ):
			i = i + 1
			titleFile = os.path.join( gOutDir, DEC_BOOKS_DIR, safeTitle + '_' + str( i ) + EXT_EPUB )
		if i != 0:
			print( '[W] File already exists: ' + safeTitle + EXT_EPUB )

	try:
		os.rename( decFile, titleFile )
	except Exception as e:
		print( "[E] Can't rename book to " + os.path.basename( titleFile ) + " (" + str( e ) + ")" )
		return False

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
		zf = ZipFile( bookFile )
		ret = zf.testzip()
		if ret is None:
			return True
		else:
			return False
	except:
		return False

def DeleteBook( bookId ):
	if not bookId in gLibraryItems.keys():
		print( "[E] Can't delete book: wrong book ID " + bookId )
		return False

	print( "      Delete book: " + bookId )

	result = True
	bookFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_EPUB )
	lcplFile = os.path.join( gOutDir, ENC_BOOKS_DIR, bookId + EXT_LCPL )
	decFile = os.path.join( gOutDir, DEC_BOOKS_DIR, bookId + EXT_EPUB )
	title = gLibraryItems[ bookId ][ LIBITEM_IDX_TITLE ]
	titleFile = os.path.join( gOutDir, DEC_BOOKS_DIR, title + EXT_EPUB )

	fileToDel = [ bookFile, lcplFile, decFile, titleFile ]
	for f in glob.glob( os.path.join( gOutDir, DEC_BOOKS_DIR, title + "_*" + EXT_EPUB ) ):
		if re.search( title + '_\d+\\' + EXT_EPUB, f ) is not None:
			fileToDel.append( f )

	try:
		for fDel in fileToDel:
			if os.path.isfile( fDel ):
				os.remove( fDel )
#				print( '        DEL ' + os.path.basename( fDel ) )
	except:
		print( "[E] Can't delete file: " + f )
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
		for line in open( dls, "r", encoding="utf-8" ):
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
		print( "" )

	if len( todec ) > 0:
		print( "[I] Books to be decrypted: " + str( len( todec ) ) )
		decok = 0
		decng = 0
		for bookId in todec:
			ret = DecryptBook( bookId )
			if ret == EResult.OKAY:
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
		print( "" )
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
					print( "" )
				elif result == EResult.NO_GOOD:
					dlng = dlng + 1
					print( "" )
				elif result == EResult.SKIP:
					dlskip = dlskip + 1

	
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

def DownlooadLibraryItems():
	print( "[I] Download library items" )
	dlurl = SECRET2
	fileIndex = ''

	while True:
		try:
			response = requests.get( dlurl, verify=gSslVerify, proxies=gProxy, headers=gHttpHeader )
		except Exception as e:
			print( "[E]   Can't download library items! (" + str( e ) + ")" )
			return EResult.NO_GOOD

		if response.status_code == 200:
			if fileIndex == '':
				fn = LIBRARY_ITEMS_FILE_NAME + EXT_JSON
			else:
				fn = "%s_%s%s" % ( LIBRARY_ITEMS_FILE_NAME, fileIndex, EXT_JSON )
			with open( os.path.join( gOutDir, fn ), "w", encoding = "utf-8" ) as f:
				f.writelines( response.text )

			print( "[I] Saved library items to file: " + fn )
			jsobj = json.loads( response.text )
			if 'links' in jsobj:
				if jsobj[ 'links' ][ 'next' ] is None:
					return EResult.OKAY

				dlurl = jsobj[ 'links' ][ 'next' ]
				fileIndex = dlurl.split( '=' )[ -1 ]

			else:
				return EResult.OKAY
		else:
			return EResult.NO_GOOD

def NeedDlLibitems():
	libitemFile = os.path.join( gOutDir, LIBRARY_ITEMS_FILE_NAME + EXT_JSON )
	try:
		lastMod = datetime.utcfromtimestamp( os.path.getmtime( libitemFile ) )
	except:
		return True

	return False			# comment out this line for periodic checking for new items

	if (datetime.now() - lastMod).days > REDOWNLOAD_LIBITEM_DAYS:
		dlurl = SECRET13 + lastMod.strftime( '%Y-%m-%dT%H:%M:%S.122Z' ) + SECRET14
		try:
			response = requests.get( dlurl, verify=gSslVerify, proxies=gProxy, headers=gHttpHeader )
			if response.status_code == 200:
				jsObj = json.loads( response.text )
				if jsObj[ 'meta' ][ 'total_count' ] > 0:
					return True
				else:
					modTime = time.mktime( datetime.now().timetuple() )
					os.utime( libitemFile, (modTime, modTime) )
					return False
		except:
			pass

		return False
	else:
		return False

def LoadLibraryItems():
	if gRedlLibitems or NeedDlLibitems():
		if DownlooadLibraryItems() != EResult.OKAY:
			return False

	bDone = False
	fileIndex = ''

	while not bDone:
		if fileIndex == '':
			fn = LIBRARY_ITEMS_FILE_NAME + EXT_JSON
		else:
			fn = "%s_%s%s" % ( LIBRARY_ITEMS_FILE_NAME, fileIndex, EXT_JSON )
		libitemFile = os.path.join( gOutDir, fn )
		try:
			with open( libitemFile, "r", encoding = "utf-8" ) as f:
				jsObj = json.load( f )
		except Exception as e:
			print( "[E] Can't load library items! (" + str( e ) + ")" )
			return False

		if fileIndex == '':
			lastModify = jsObj[ 'meta' ][ 'last_modified' ]
			totalCount = jsObj[ 'meta' ][ 'total_count' ]

		for item in jsObj[ 'included' ]:
			if item[ 'type' ] == 'readings':
				id = item[ 'id' ]
				bookId = item[ 'relationships' ][ 'book' ][ 'data' ][ 'id' ]
				gLibraryItems[ bookId ] = [ id ]
				gBookIdMap[ id ] = bookId

		for item in jsObj[ 'included' ]:
			if item[ 'type' ] == 'books':
				bookId = item[ 'id' ]
				if bookId in gLibraryItems:
					title = item[ 'attributes' ][ 'title' ]
					author = item[ 'attributes' ][ 'author' ]
					gLibraryItems[ bookId ].append( title )
					gLibraryItems[ bookId ].append( author )
				else:
					print( "[W] Unmapped book ID: " + bookId )

		for item in jsObj[ 'data' ]:
			id = item[ 'relationships' ][ 'reading' ][ 'data' ][ 'id' ]
			lic = item[ 'attributes' ][ 'urls' ][ 'license' ]
			archived = item[ 'attributes' ][ 'archive' ]
			if id in gBookIdMap:
				bookId = gBookIdMap[ id ]
				gLibraryItems[ bookId ].append( lic )
				gLibraryItems[ bookId ].append( archived )
			else:
				print( "[W] Unmapped ID for license url: " + id )

		print( "[I] Library items loaded from file: " + libitemFile )
#		print( "      Last Modified: " + lastModify )
		print( "      Total Count = " + str( totalCount ) )

		if 'links' in jsObj:
			if jsObj[ 'links' ][ 'next' ] is None:
				bDone = True
			else:
				fileIndex = jsObj[ 'links' ][ 'next' ].split( '=' )[ -1 ]
		else:
			bDone = True

	return True

def SaveAccessToken():
	if os.path.isfile( os.path.join( gOutDir, TOKEN_FILE_NAME ) ):
		print( "[I] Token file already exists. Skip saving" )
		return True

	try:
		with open( os.path.join( gOutDir, TOKEN_FILE_NAME ), "w" ) as f:
			f.write( gAccessToken )
			f.write( "\n" )
		print( "[I] Token saved to file" )
		return True
	except Exception as e:
		print( "[W] Can't write token file! (" + str( e ) + ")" )
		return False

def ParseArgument():
	global gOutDir, gSslVerify, gNeedProcess, gDownloadAll, gDownloadNew, gDecryptAll, gProxy, gMapFile, gMaxDownload
	global gGenBooklistDec, gGenBooklistRaw
	global gAccessToken, gDecOverwrite, gRedlLibitems

	parser = argparse.ArgumentParser()
	parser.add_argument( "-d", "--dldec", action="store_true", help="Download/decrypt books according to download sheet" )
	parser.add_argument(       "--dlall", action="store_true", help="Download all books" )
	parser.add_argument(       "--dlnew", action="store_true", help="Download books that have not downloaded yet" )
	parser.add_argument(       "--decall", action="store_true", help="Decrypt all downloaded books" )
	parser.add_argument( "-o", "--out", help="Output directory", default="." )
	parser.add_argument( "-m", "--map", help="Specify title/author map file" )
	parser.add_argument( "-t", "--token", help="Specify token (will be saved into " + TOKEN_FILE_NAME + ")" )
	parser.add_argument(       "--proxy-host", help="Proxy IP address" )
	parser.add_argument(       "--proxy-port", help="Proxy port number", type=int )
	parser.add_argument(       "--proxy-user", help="Proxy user name" )
	parser.add_argument(       "--proxy-password", help="Proxy password" )
	parser.add_argument(       "--no-verify", action="store_true", help="Do not verify SSL CA" )
	parser.add_argument( "-n", "--numdl", type=int, help="Max number of downloads" )
	parser.add_argument( "-l", "--list", action="store_true", help="Generate book list for decrypted books" )
	parser.add_argument(       "--list-raw", action="store_true", help="Generate book list for downloaded books" )
	parser.add_argument(       "--no-overwrite", action="store_true", help="Do not overwrite existing decrypted file" )
	parser.add_argument( "-r", "--redl", action="store_true", help="Re-download library items" )

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

	if args.token and len( args.token ) > 0:
		gAccessToken = args.token
		SaveAccessToken()

	if args.numdl:
		gMaxDownload = args.numdl

	if args.list:
		gGenBooklistDec = True

	if args.list_raw:
		gGenBooklistRaw = True

	if args.no_overwrite:
		gDecOverwrite = False

	if args.redl:
		gRedlLibitems = True

def BuildHttpHeader():
	global gAccessToken, gHttpHeader

	if gAccessToken is None:
		try:
			gAccessToken = RetrieveToken()
			if gAccessToken is not None:
				SaveAccessToken()
		except Exception as e:
			print( "[E] Can't retrieve access token from system: " + str( e ) )
			pass

	if gAccessToken is None:
		try:
			with open( os.path.join( gOutDir, TOKEN_FILE_NAME ), "r" ) as f:
				gAccessToken = f.read().rstrip()
				print( "[I] Token loaded from file: " + gAccessToken )
		except Exception as e:
			print( "[E] Can't load token from file! (" + str( e ) + ")" )
			return False

	gHttpHeader = {
		SECRET11 : SECRET6,
		SECRET12 : SECRET7 + gAccessToken
	}

	return True

def RetrieveToken():
	count = 0
	token = None
	seq = -1
	kvPair = ParseLdbDir( os.path.join( os.getenv( SECRET10 ), SECRET3, SECRET4 ) )
	for k in kvPair:
		if k.endswith( SECRET5 ):
			print( '[I] Token retrieved from system: ' + kvPair[ k ][ 0 ] )		#  + " (KEY=" + k + ", SEQ=" + str( kvPair[ k ][ 1 ] ) +")" )
			count = count + 1
			if kvPair[ k ][ 1 ] > seq:
				seq = kvPair[ k ][ 1 ]
				token = kvPair[ k ][ 0 ]

	if count > 1:
		print( '[W] Found more than one token. Use token: ' + token )

	return token

def RetrievePrivateKey():
	fileName = os.path.join( os.getenv( SECRET10 ), SECRET3, SECRET9 );
	try:
		with open( fileName, "rb" ) as f:
			data = f.read()
	except:
		print( "[W] Can't read file: " + fileName )
		return None

	try:
		iv = data[ : 16 ]
		saltBytes = iv.decode( errors='replace' ).encode( 'utf-8' )
		passwd = hashlib.pbkdf2_hmac( 'sha512', SECRET8, saltBytes, 10000, 32 )
		jsData = AES( passwd, iv ).decrypt( data[ 17: ] )
		numPad = jsData[ -1 ]
		if (numPad > 0) and (numPad <= 16):
			jsData = jsData[ : numPad * -1 ]
		jsObj = json.loads( jsData )
		privateKey = jsObj[ SECRET15 ]

		return privateKey

	except Exception as e:
		print( "[W] Can't retrieve private key from " + os.path.basename( fileName )  + " (" + str( e ) + ")" );
		return None;

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

def dldecm00v2Main():
	global AES, RSA

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

	ParseArgument()

	if not BuildHttpHeader():
		sys.exit( 1 )

	if not LoadLibraryItems():
		sys.exit( 1 )

	if not CheckBookDir():
		sys.exit( 1 )

	if not CollectKeys():
		sys.exit( 1 )
	
	if gGenBooklistDec:
		GenerateDecBooklist()
		sys.exit( 0 )
	elif gGenBooklistRaw:
		GenerateRawBooklist()
		sys.exit( 0 )
	elif gNeedProcess:
		ParseAuthorTitleMap( gMapFile )
		ProcessDownloadSheet()

	GenerateDownloadSheet()
	return 0

if __name__ == '__main__':
	sys.exit( dldecm00v2Main() )
