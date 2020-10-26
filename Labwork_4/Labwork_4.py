from sympy import *
import libnum
import hashlib

class elg_:

    data = ['p', 'g', 'y', 'x']

    def sign(self, M, K):
        c_1 = pow(self.g, K, self.p) #c_1 = (g^k) mod p
        #M is hash; c_2=(M*((y^k) mod p)) mod p
        c_2 = (int.from_bytes(M,"big") * pow(self.y, K, self.p)) % self.p
        return (c_1, c_2)

    def verify(self, M, sig):
        '''
M - hash;
sig - signature [c_1,c_2]
    	'''
        #due to M=(c_2/(c_1^x)) mod p putting a tremendous strain on my CPU a
    	#roundabound way was found
        #starting from here
        r = randprime(2, self.p - 1)
        b = (sig[0] * pow(self.g, r, self.p)) % self.p
        ax = pow(b, self.x, self.p)
        buf = (sig[1] * libnum.invmod(ax, self.p)) % self.p
        val_1 = (buf * pow(self.y, r, self.p)) % self.p
        #to over here
        print("Received hash:",val_1,sep="\n")
        val_2 = int.from_bytes(M,"big")
        #Comparison of received and calculated
        if val_1 == val_2:
            return 1
        return 0

def keys(floor,ceil):

    obj = elg_() #object, which contains ['p', 'g', 'y', 'x']
    obj.g = randprime(floor,ceil) #random prime number in range [floor,ceil]
    obj.p = randprime(floor,ceil) #random prime number in range [floor,ceil]
    if (obj.g > obj.p):
        obj.g,obj.p = obj.p,obj.g #if g is greater then p they swap

    print("*" * 10,"p=" + str(obj.p),"g=" + str(obj.g),"*" * 10,sep="\n")

    # Generate private key x
    obj.x = randprime(2, obj.p - 1)
    # Generate public key y
    obj.y = pow(obj.g, obj.x, obj.p)
    print("*" * 10,"y=" + str(obj.y),"*" * 10,sep="\n")
    return obj

size = 256
#if message is not null
t = true
#message
while t:
    message = input("Your message:")
    if message: t = false
hash = hashlib.sha512(message.encode("utf8")).digest()
print("hash:",int.from_bytes(hash,"big"),sep="\n")
if (len(str(int.from_bytes(hash,"big"))) > size):
    print("Message can't be signed with current 'size' value.")
else:
    key = keys(pow(10,size - 1),pow(10,size)) 
    while 1:
        k = randprime(pow(10,size - 1),key.p - 1)
        if gcd(k,key.p - 1) == 1: break
    print("*" * 10,"k=" + str(k),"*" * 10,sep="\n")
    signature = key.sign(hash,k)
    print("C1:",signature[0],"C2:",signature[1],sep="\n")
    if key.verify(hash,signature):
        print("Data is OK")
    else:
        print("Error")