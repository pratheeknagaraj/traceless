import hashlib
import random
import requests
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto import Random

def main():
	pass

def suscribe():
	pass

def client_update():
	pass

def init_conversation():
	pass

def conversation_update():
	pass

''' You may want to change up these headers, don't know how you want to implement'''

def create_message():

def read_message(signature, ciphertext, other_user_public_key, my_key): #assumes other_user_public_key is tuple of form (n,e), my_key is of form (n,e,d)
    checksum_n = other_user_public_key[0]
    checksum_e = other_user_public_key[1]
    if PKCS1_verify(signature, message, checksum_n, checksum_e) != True:
        return 'Message could not be verified'
    n = my_key[0]
    e = my_key[1]
    d = my_key[2]
    plaintext = RSA_decrypt(ciphertext, n, e, d)
    return plaintext

def write_message()
def send_message():
    pass

def collect_messages():
	pass

def timer(method):
	pass

def send_request():
	pass


def RSA_keygen():
    key = RSA.generate(2048)
    return key.n, key.e, key.d #returns RSA key object, n, e (both public) and secret key d

def RSA_encrypt(message, n, e): #takes in message, n, and e
    current_key = RSA.construct((n,e))
    k = random.getrandbits(2048)
    return current_key.encrypt(message, k)

def RSA_decrypt(message, n, e, d):
    key = RSA.construct((n,e,d))
    return key.decrypt(message)

def PKCS1_sign(message, n, e, d):
    key = RSA.construct((n,e,d))
    h = SHA.new()
    h.update(message)
    signer = PKCS1_PSS.new(key)
    signature = signer.sign(h)
    return signature

def PKCS1_verify(signature, message, n, e):
    h = SHA.new()
    h.update(message)
    public_key = RSA.construct((n,e))
    verifier = PKCS1_PSS.new(public_key)
    return verifier.verify(h, signature)

# ----- Extended Euclidean Algorithm ----
## From Wikibooks - https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
 
def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m
# ----- End ------

def H(m):
    """
   return hash (256-bit integer) of string m, as long integer.
   If the input is an integer, treat it as a string.
   """
    m = str(m)
    return int(hashlib.sha256(m).hexdigest(),16)


 