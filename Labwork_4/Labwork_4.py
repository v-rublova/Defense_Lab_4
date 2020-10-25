from sympy import *
import libnum
import hashlib
import random

class elg_:

    data = ['p', 'g', 'y', 'x']

    def sign(self, M, K):
        c_1 = pow(self.g, K, self.p)
        c_2 = (int.from_bytes(M,"big") * pow(self.y, K, self.p)) % self.p
        return (c_1, c_2)

    def verify(self, M, sig):
        r = randprime(2, self.p - 1)
        a_blind = (sig[0] * pow(self.g, r, self.p)) % self.p
        ax = pow(a_blind, self.x, self.p)
        plaintext_blind = (sig[1] * libnum.invmod(ax, self.p)) % self.p
        val_1 = (plaintext_blind * pow(self.y, r, self.p)) % self.p    
        val_2 = int.from_bytes(M,"big")
        if val_1 == val_2:
            return 1
        return 0

def keys(floor,ceil):
    obj = elg_()
    obj.g = randprime(floor,ceil)
    obj.p = randprime(floor,ceil)
    if (obj.g > obj.p):
        obj.g,obj.p = obj.p,obj.g 
    # Generate private key x
    obj.x = randprime(2, obj.p - 1)
    # Generate public key y
    obj.y = pow(obj.g, obj.x, obj.p)
    return obj

bit_size = 512
message = "Hi"
key = keys(pow(10,bit_size - 1),pow(10,bit_size))
hash = hashlib.sha512(message.encode("utf8")).digest()
print(hash)
while 1:
    k = randprime(pow(10,bit_size - 1),key.p - 1)
    if gcd(k,key.p - 1) == 1: break
signature = key.sign(hash,k)
if key.verify(hash,signature):
    print("OK")
else:
    print("Incorrect signature")