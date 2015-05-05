import random
from traceless_math import *

class UST:

    def __init__(self, server_pk_n, server_pk_e):
        self.server_pk_n = server_pk_n
        self.server_pk_e = server_pk_e
        self.nonce = None
        self.signature = None

    def blind(self,nonce):
        R, self.mod_inv = self.inverse()
        return (power(R, self.server_pk_e, self.server_pk_n) * nonce) % self.server_pk_n

    def unblind(self,blinded_sign):
        return (self.mod_inv * blinded_sign) % self.server_pk_n

    def prepare(self,nonce=None):
        if nonce == None:
            self.new_nonce = random.getrandbits(256)
        else:
            self.new_nonce = nonce
        self.blinded_nonce = self.blind(self.new_nonce)

    def receive(self, blinded_sign):
        (self.nonce, self.signature) = (self.new_nonce, self.unblind(blinded_sign))

    def inverse(self):
        R = None
        mod_inv = None
        while True:
            R = random.getrandbits(128)
            mod_inv = modinv(R, self.server_pk_n)
            if mod_inv != None:
                break
        return R, mod_inv
