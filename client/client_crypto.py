from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
import random
import base64

def RSA_gen(size=4096):
    return RSA.generate(size)

def RSA_gen_user(user):
    return RSA.construct((user.pk_n,user.pk_e))

def RSA_gen_user_sign(user):
    return RSA.construct((user.pk_sign_n,user.pk_sign_e))

def RSA_keys(rsa):
    return rsa.n, rsa.e, rsa.d #returns RSA key object, n, e (both public) and secret key d

def RSA_encrypt(message, rsa): #takes in message, n, and e
    k = random.getrandbits(2048)
    return base64.encodestring(rsa.encrypt(message, k)[0])

def RSA_decrypt(message, rsa):
    return rsa.decrypt(base64.decodestring(message))

def PKCS1_sign(message, rsa):
    h = SHA.new()
    h.update(message)
    signer = PKCS1_PSS.new(rsa)
    signature = signer.sign(h)
    return base64.encodestring(signature)

def PKCS1_verify(signature, message, rsa):
    h = SHA.new()
    h.update(base64.decodestring(message))
    verifier = PKCS1_PSS.new(rsa)
    return verifier.verify(h, signature)