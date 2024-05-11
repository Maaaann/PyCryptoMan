"""
Project Name: Digital Signature for Firmware Security
Description: SecureFirm ensures firmware integrity through digital signatures.
Author: Altayeb
Course Name: Cycle '3' Cryptography
Instructor: Mohamed Tarek
Date Created: May 7, 2024
Python Version: 3.12.3
GitHub: https://github.com/abdelrahmaneltayeb/PyCryptog
LinkedIn: https://www.linkedin.com/in/abdelrahmanaltayeb/
"""

import sys
from hashlib import sha256
from Crypto.Util.number import bytes_to_long

#_____________Usage___________#
usage = "==== USAGE ====\n> python verify.py firmwareFile.txt signature.txt public.key"
if len(sys.argv) < 2:
    print(usage)
    exit()
#_____________Accepting_The_Public_KEY___________#
pubKey = sys.argv[3]

with open(pubKey, "rb") as pk :
    e = int(pk.readline())
    n = int(pk.readline())

#_______Accepting_Firmware_File_As_Argument_______#
firmwareFile = sys.argv[1]

with open(firmwareFile,"rb") as file:
    firmware = file.read()

#_______Hashing_The_FIRMWARE_Useing_SHA256_______#
hash = sha256()
hash.update(firmware)
hash.digest()
H = bytes_to_long(hash.digest())

#_______Accepting_Signature_File_As_Argument_______#
signatureFile = sys.argv[2]

with open(signatureFile,"rb") as file:
    signature = int(file.read())

#___________Calculating_The_Signature____________#
verifySignature = pow(signature, e , n)

#___________Verifying_The_Signature____________#
if verifySignature == H :
    print("verification succeeded!")
else:
    print("verification failed!")
