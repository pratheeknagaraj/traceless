import random

class UST:

    def __init__(self, server_pk_n, server_pk_e):
        self.server_pk_n = server_pk_n
        self.server_pk_e = server_pk_e
        self.nonce = None
        self.signature = None

        self.new_nonce = random.getrandbits(2048)
        self.blinded_nonce = blind(start_nonce)

    def blind(self,nonce):
        message, self.mod_inv = self.inverse(nonce)
        return power(message, self.server_pk_e, self.server_pk_n) * \
               power(nonce, self.server_pk_e, self.server_pk_n)

    def unblind(self,blinded_sign):
        return (self.mod_inv * blinded_sign) % self.server_pk_n

    def prepare(self):
        self.new_nonce = random.getrandbits(2048)
        self.blinded_nonce = blind(self.new_nonce)

    def receive(self, blinded_sign):
        (self.nonce, self.signature) = (self.new_nonce, self.unblind(blinded_sign))

    def inverse(n):
        message = None
        mod_inv = None
        while True:
            message = random.getrandbits(2048)
            mod_inv = modinv(message, n)
            if mod_inv != None:
                break
        return message, mod_inv