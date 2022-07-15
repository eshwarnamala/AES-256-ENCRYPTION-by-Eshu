'''
Usage: 
python aes.py <encrypt/decrypt> <message/cipher> <key> <keytype> 
'''

'''
first install the requirements using pip
e.g. pip install pycryptodome...
you can install all the requirements as well...
'''
#Lets's get started..

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random


def encrypt(key, source, encode=True, keyType = 'hex'):
	'''
	key - The key to encrypt the message.
	encode - To encode the output in base64. Default is true
	keyType - Specify the type of key passed

	Returns:
	Base64 encoded cipher
	
	'''

	source = source.encode()
	if keyType == "hex":
		# Convert key (in hex representation) to bytes 
		key = bytes(bytearray.fromhex(key))
	else:
		# SHA-256 over our key to get a proper-sized AES key.
		key = key.encode()
		key = SHA256.new(key).digest()

	IV = Random.new().read(AES.block_size)  # IV generation
	encryptor = AES.new(key, AES.MODE_CBC, IV)
	padding = AES.block_size - len(source) % AES.block_size  # calculate required padding to encrypt
	source += bytes([padding]) * padding  
	data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
	return base64.b64encode(data).decode() if encode else data


def decrypt(key, source, decode=True,keyType="hex"):

	source = source.encode()
	if decode:
		source = base64.b64decode(source)

	if keyType == "hex":
		# Convert key to bytes
		key = bytes(bytearray.fromhex(key))
	else:
		
		key = key.encode()
		key = SHA256.new(key).digest()  

	IV = source[:AES.block_size]  # extract the IV from the beginning
	decryptor = AES.new(key, AES.MODE_CBC, IV)
	data = decryptor.decrypt(source[AES.block_size:])
	padding = data[-1]  # pick the padding value from the end
	if data[-padding:] != bytes([padding]) * padding:  
		raise ValueError("Padding Error!!!...")
	return data[:-padding]  # remove the padding





# pass a message and a key(which is 'hex' representation) to encrypt
message = "Hi Hello, this is Eshwar Namala. Presenting you my first github repository,which is about AES 256 Encryption. Follow for more like this!!!...." 
key = "98076ffea203325acdeefa200964acd8da6fd5aaffea902616745effac62d789" # 64 bit hex key 

# encrypt now.....
encrypted = encrypt(key=key,source=message) 

# to decrypt 
decrypted = decrypt(key=key,source=encrypted)
print(encrypted)
print(decrypted)

'''
for better understanding you can encrypt the message first without using the above decrypted .......
Then you will get the encrypted message in the output terminal...
Now copy that encrypted message and now pass that to a variable and then passs to source,,
Then you will get the Actual message...




If you still have any doubts let me know....
signing off.....
~eshu.
'''
