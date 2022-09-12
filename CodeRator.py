#!/usr/bin/env python3

from Crypto.Cipher import AES
import argparse
import random
import base64
import binascii
try:
	import hashlib
except ImportError:
	sys.exit("Please install 'hashlib' module: pip install hashlib")

the_parser = argparse.ArgumentParser(
	prog='\033[1;34mCodeRator',
	usage='./CodeRator [Actions] [Type of encoding]',
	description='A simple script whose purpose is to randomly generate or create a hash value, and also has the ability to encode and decode the code in Base64.',
	add_help=False,
	epilog='Created by F3ng-L0 - \033[1;95m https://github.com/F3ng-L0'
	)

the_parser.add_argument('-val', '--value', action='store', help='Enter with your value')
the_parser.add_argument('-e', '--encode', action='store_true', help='Encode your value')
the_parser.add_argument('-d', '--decode', action='store_true', help='Decode your value(Just for Base64)')
the_parser.add_argument('-g', '--generate', action='store_true', help='Generate a random hash')
the_parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0', help="Show program's version number and exit.")
the_parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show help message and exit.')
# ---- # ---- #
the_parser.add_argument('-b4', '--base64', action='store_true', help='Encode or decode in Base64')
the_parser.add_argument('--MD5', action='store_true', help='Generate or encode/decode MD5 hash')
the_parser.add_argument('--SHA1', action='store_true', help='Generate or encode/decode SHA1 hash')
the_parser.add_argument('--SHA224', action='store_true', help='Generate or encode/decode SHA224 hash')
the_parser.add_argument('--SHA256', action='store_true', help='Generate or encode/decode SHA256 hash')
the_parser.add_argument('--SHA384', action='store_true', help='Generate or encode/decode SHA383 hash')
the_parser.add_argument('--SHA512', action='store_true', help='Generate or encode/decode SHA512 hash')

args = the_parser.parse_args()

try:
	value = args.value

	if args.encode:
		if args.MD5:
			print('\033[1;33m MD5:', hashlib.md5(value.encode()).hexdigest())
		elif args.SHA1:
			print('\033[1;33m SHA1:', hashlib.sha1(value.encode()).hexdigest())
		elif args.SHA224:
			print('\033[1;33m SHA224:', hashlib.sha224(value.encode()).hexdigest())
		elif args.SHA256:
			print('\033[1;33m SHA256:', hashlib.sha256(value.encode()).hexdigest())
		elif args.SHA384:
			print('\033[1;33m SHA384:', hashlib.sha384(value.encode()).hexdigest())
		elif args.SHA512:
			print('\033[1;33m SHA512:', hashlib.sha512(value.encode()).hexdigest())
		elif args.base64:
			message = value
			message_bytes = message.encode('ascii')
			base64_bytes = base64.b64encode(message_bytes)
			base64_message = base64_bytes.decode('ascii')
			print('\033[1;33m Base64: ', base64_message)

	if args.decode:
		base64_message = value
		base64_bytes = base64_message.encode('ascii')
		message_bytes = base64.b64decode(base64_bytes)
		message = message_bytes.decode('ascii')
		print('\033[1;33m Base64 Decoded: ', message)


	if args.generate:
		if args.MD5:
			print('\033[1;33m MD5: ', random.getrandbits(128))
		elif args.SHA1:
			print('\033[1;33m SHA1: ', random.getrandbits(160))
		elif args.SHA224:
			print('\033[1;33m SHA224: ', random.getrandbits(112))
		elif args.SHA256:
			print('\033[1;33m SHA256: ', random.getrandbits(256))
		elif args.SHA384:
			print('\033[1;33m SHA384: ', random.getrandbits(512))


except KeyboardInterrupt:
	sys.exit('\n\033[1;31mYou pressed Ctrl+C')

except binascii.Error as err:
	print('\033[1;31mError !')
