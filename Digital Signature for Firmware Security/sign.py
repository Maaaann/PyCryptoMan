"""
Project Name: Digital Signature for Firmware Security
Description: SecureFirm ensures firmware integrity through digital signatures, using RSA
Author: Altayeb
Course Name: Cycle '3' Cryptography
Instructor: Mohamed Tarek
Date Created: May 7, 2024
Python Version: 3.12.3
GitHub: https://github.com/abdelrahmaneltayeb/PyCryptoMan
LinkedIn: https://www.linkedin.com/in/abdelrahmanaltayeb/
"""
#___________________How to run__________________#
# python script.py path/to/your/Firmwarefile.txt
#-----------------------------------------------#


import sys
from hashlib import sha256
from Crypto.Util.number import getPrime, bytes_to_long

#_______Taking_Firmware_File_As_Argument_______#
firmwareFile = sys.argv[1]

with open(firmwareFile,"rb") as file:
    firmware = file.read()

#_______Hashing_The_FIRMWARE_Using_SHA256_______#
hash = sha256()
hash.update(firmware)
hash.digest()   # shasum
H = bytes_to_long(hash.digest())

#_______Generating_RSA_Parameters_______#
p, q = getPrime(1024) , getPrime(1024)  # 112 security bits (level) --> minimum acceptable
n = p * q
e = 2**16 + 1  # it's recommended to use 2 **16 + 1
phi = (p-1)*(q-1)  # totient => n
d = pow(e, -1, phi)

#---------------------------------------------#
#______PUBLIC_KEY_____# #______PRIVATE_KEY____#
#________(e,n)________# #________(d,n)________#
#---------------------------------------------#

#____Generating_signature_With_the_Private_Key____#
signature = pow(H, d, n)  #  H**d % n

#_________Storing_The_Signature_In_File___________#
signatureFile = open("signature.txt", "w")
signatureFile.write(str(signature))


#_________Storing_The_PUBLIC_KEY_In_File_________#
with open("public.key", "w") as f:
    f.write(str(e) + "\n" )
    f.write(str(n))

