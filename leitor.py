from PyKCS11 import *
from PyKCS11.LowLevel import *
lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()
for slot in slots:
    print (pkcs11.getTokenInfo(slot))