from pyDes import *
import sys
import getopt

#############################################################################
# 				Examples				    #
#############################################################################
def _example_triple_des_():
	from time import time

	# Utility module
	from binascii import unhexlify as unhex

	# example shows triple-des encryption using the des class
	print ("Example of triple DES encryption in default ECB mode (DES-EDE3)\n")

	print ("Triple des using the des class (3 times)")
	t = time()
	k1 = des(unhex("133457799BBCDFF1"))
	k2 = des(unhex("1122334455667788"))
	k3 = des(unhex("77661100DD223311"))
	d = "Triple DES test string, to be encrypted and decrypted..."
	print ("Key1:      %r" % k1.getKey())
	print ("Key2:      %r" % k2.getKey())
	print ("Key3:      %r" % k3.getKey())
	print ("Data:      %r" % d)

	e1 = k1.encrypt(d)
	e2 = k2.decrypt(e1)
	e3 = k3.encrypt(e2)
	print ("Encrypted: %r" % e3)

	d3 = k3.decrypt(e3)
	d2 = k2.encrypt(d3)
	d1 = k1.decrypt(d2)
	print ("Decrypted: %r" % d1)
	print ("DES time taken: %f (%d crypt operations)" % (time() - t, 6 * (len(d) / 8)))
	print ("")

	# Example below uses the triple-des class to achieve the same as above
	print ("Now using triple des class")
	t = time()
	t1 = triple_des(unhex("133457799BBCDFF1112233445566778877661100DD223311"))
	print ("Key:       %r" % t1.getKey())
	print ("Data:      %r" % d)

	td1 = t1.encrypt(d)
	print ("Encrypted: %r" % td1)

	td2 = t1.decrypt(td1)
	print ("Decrypted: %r" % td2)

	print ("Triple DES time taken: %f (%d crypt operations)" % (time() - t, 6 * (len(d) / 8)))

def _example_des_():
	from time import time

	# example of DES encrypting in CBC mode with the IV of "\0\0\0\0\0\0\0\0"
	print ("Example of DES encryption using CBC mode\n")
	t = time()
	k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0")
	data = "DES encryption algorithm"
	print ("Key      : %r" % k.getKey())
	print ("Data     : %r" % data)

	d = k.encrypt(data)
	print ("Encrypted: %r" % d)

	d = k.decrypt(d)
	print ("Decrypted: %r" % d)
	print ("DES time taken: %f (6 crypt operations)" % (time() - t))
	print ("")

def _filetest_():
	from time import time

	f = open("pyDes.py", "rb+")
	d = f.read()
	f.close()

	t = time()
	k = des("MyDESKey")

	d = k.encrypt(d, " ")
	f = open("pyDes.py.enc", "wb+")
	f.write(d)
	f.close()
	
	d = k.decrypt(d, " ")
	f = open("pyDes.py.dec", "wb+")
	f.write(d)
	f.close()
	print ("DES file test time: %f" % (time() - t))
	
def _profile_():
	try:
		import cProfile as profile
	except:
		import profile
	profile.run('_fulltest_()')
	#profile.run('_filetest_()')

def _fulltest_():
	# This should not produce any unexpected errors or exceptions
	from time import time
	from binascii import unhexlify as unhex
	from binascii import hexlify as dohex

	t = time()

	data = "DES encryption algorithm".encode('ascii')
	k = des("\0\0\0\0\0\0\0\0", CBC, "\0\0\0\0\0\0\0\0")
	d = k.encrypt(data)
	if k.decrypt(d) != data:
		print ("Test 1:  Error: decrypt does not match. %r != %r" % (data, k.decrypt(d)))
	else:
		print ("Test 1:  Successful")

	data = "Default string of text".encode('ascii')
	k = des("\0\0\0\0\0\0\0\0", CBC, "\0\0\0\0\0\0\0\0")
	d = k.encrypt(data, "*")
	if k.decrypt(d, "*") != data:
		print ("Test 2:  Error: decrypt does not match. %r != %r" % (data, k.decrypt(d)))
	else:
		print ("Test 2:  Successful")

	data = "String to Pad".encode('ascii')
	k = des("\r\n\tABC\r\n")
	d = k.encrypt(data, "*")
	if k.decrypt(d, "*") != data:
		print ("Test 3:  Error: decrypt does not match. %r != %r" % (data, k.decrypt(d)))
	else:
		print ("Test 3:  Successful")

	k = des("\r\n\tABC\r\n")
	d = k.encrypt(unhex("000102030405060708FF8FDCB04080"), unhex("44"))
	if k.decrypt(d, unhex("44")) != unhex("000102030405060708FF8FDCB04080"):
		print ("Test 4a: Error: Unencypted data block does not match start data")
	elif k.decrypt(d) != unhex("000102030405060708FF8FDCB0408044"):
		print ("Test 4b: Error: Unencypted data block does not match start data")
	else:
		print ("Test 4:  Successful")

	data = "String to Pad".encode('ascii')
	k = des("\r\n\tkey\r\n")
	d = k.encrypt(data, padmode=PAD_PKCS5)
	if k.decrypt(d, padmode=PAD_PKCS5) != data:
		print ("Test 5a: Error: decrypt does not match. %r != %r" % (data, k.decrypt(d)))
	# Try same with padmode set on the class instance.
	k = des("\r\n\tkey\r\n", padmode=PAD_PKCS5)
	d = k.encrypt(data)
	if k.decrypt(d) != data:
		print ("Test 5b: Error: decrypt does not match. %r != %r" % (data, k.decrypt(d)))
	else:
		print ("Test 5:  Successful")

	# Test PAD_PKCS5 with CBC encryption mode.

	k = des("IGoodKey", mode=CBC, IV="\0\1\2\3\4\5\6\7")
	data = "String to Pad".encode('ascii')
	d = k.encrypt(data, padmode=PAD_PKCS5)
	if k.decrypt(d, padmode=PAD_PKCS5) != data:
		print ("Test 12: Error: decrypt does not match. %r != %r" % (data, k.decrypt(d)))
	else:
		print ("Test 12: Successful")

	k = des("IGoodKey", mode=CBC, IV="\0\1\2\3\4\5\6\7")
	data = "String not need Padding.".encode('ascii')
	d = k.encrypt(data, padmode=PAD_PKCS5)
	if k.decrypt(d, padmode=PAD_PKCS5) != data:
		print ("Test 13: Error: decrypt does not match. %r != %r" % (data, k.decrypt(d)))
	else:
		print ("Test 13: Successful")

	print ("")
	print ("Total time taken: %f" % (time() - t))

def main(argv):
   inputfile = ''
   outputfile = ''
   if not argv:
     print 'brut.py -k <hex of key> -i <inputfile> -o <outputfile>'
     sys.exit(2)
   try:
     opts, args = getopt.getopt(argv,"hk:i:o:",["ifile=","ofile="])
   except getopt.GetoptError:
     print 'brut.py -k <hex of key> -i <inputfile> -o <outputfile>'
     sys.exit(2)
   for opt, arg in opts:
     if opt == '-h':
       print 'brut.py -k FFFFB011AACC000 -i enc_msg.txt -o dec_msg_key.txt'
       print '-k is starting point for incrementing key'
       sys.exit()
     elif opt in ("-i", "--infile"):
       inputfile = arg
     elif opt in ("-o", "--ofile"):
       outfile = arg
     elif opt in ("-k", "--key"):
       start_key = arg
   raw_message=read_file(inputfile).rstrip('\r\n')
   print " ## message length is: %d" % len(raw_message)
   if len(raw_message)%8==0: padding=0
   elif (len(raw_message)+1)%8==0: padding=1
   elif (len(raw_message)+2)%8==0: padding=2
   elif (len(raw_message)+3)%8==0: padding=3
   elif (len(raw_message)+4)%8==0: padding=4
   elif (len(raw_message)+5)%8==0: padding=5
   elif (len(raw_message)+6)%8==0: padding=6
   else: padding=7
   while padding > 0:
      raw_message = raw_message + "\x00"
      padding = padding -1
   decode(start_key,raw_message)


def read_file(filename):
   content = open(filename)
   return content.read()


def decode(key,ciphertext):
   from time import time
   from binascii import unhexlify as unhex

   # example of DES encrypting in CBC mode with the IV of "\0\0\0\0\0\0\0\0"
   print (" ##  Starting DES decryption using CBC mode ##")
   print (" Input     : %r" % ciphertext)
   print ""
   t = time()
   next_string_key = key
   x = 0
   while True:
      #increment hexadecimal string
      next_string_key='{:X}'.format(long(next_string_key,16)+1).zfill(16)
      k = des(unhex(next_string_key), CBC, "\0\0\0\0\0\0\0\0")
      d = ciphertext
      decrypted = k.decrypt(d)
      x = x + 1
      if (x>49999 and x%50000==0): print (" DES time taken: %f (%d crypt operations)" % ((time() - t),x))
      if "ale" in decrypted: break
   print (" Matching Key      : %r" % k.getKey())
   print (" Decrypted Output     : %r" % decrypted)
   print (" DES time taken: %f (%d crypt operations)" % ((time() - t),x))
   print (" ##                       ##")
   print ""
   sys.exit(1)

if __name__ == '__main__':
	#_example_des_()
	#_example_triple_des_()
	#_fulltest_()
	#_filetest_()
	#_profile_()
        main(sys.argv[1:])
