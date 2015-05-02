import hashlib
import random
import requests

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
def send_message():
	pass

def read_message():
	pass

def collect_messages():
	pass

def timer(method):
	pass

def send_request():
	pass

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


 