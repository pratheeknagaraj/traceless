import hashlib
import random
import requests
import sys
import time
import thread

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto import Random

# Server Data
server_ip = '0.0.0.0'

# Errors
ERR_INVALID_USERNAME = "Invalid_Username"

# Constants
SUCCESS = "Success"
FAILED = "Failed"
TRUE = "True"
FALSE = "False"

# Wait Times
NEW_CLIENT_WAIT         = 1.000     # Wait 1 second
NEW_CLIENT_WAIT_SHORT   = 0.100     # Wait 0.1 second
NEW_CONVERSATION_WAIT   = 0.500     # Wait half a second

class User:

    def __init__(self,username,user_id,public_key):
        self.username = username
        self.user_id = user_id
        self.public_key = public_key

    def __str__(self):
        return self.username

    def __repr__(self):
        return self.username 

class Client:

    def main(self,username):

        self.user_table = {}
        self.rsa = None

        print "INPUT USERNAME:", username
        self.username = username
        self.subscribe()

        # Upon successfully suscribing begin updates
        self.updates()

    def updates(self):
        try:
            thread.start_new_thread(client_update)
            thread.start_new_thread(conversation_update)
            thread.start_new_thread(client_input)
        except:
            print "ERRROR: unable to start client threads"
            print "FATAL: client unable to update"
            sys.exit(0)

    def client_input(self):
        while True:
            cmd = raw_input("Please enter a command: ")
            handle_input(cmd)

    def handle_input(self, cmd):
        parts = cmd.split(' ', 1)
        cmd_type = parts[0]
        cmd_args = parts[1]

        if cmd_type == "1":
            print "Local User Table"
            self.print_user_table() 
        elif cmd_type == "2":
            self.init_conversation(cmd_args)
        elif cmd_type == "3":
            split = cmd_args.split(' ', 1)
            username = split[0]
            message = split[1] 
            self.send_message(username, message)
        elif cmd_type == "H":
            print "1: 1 - Print Local User Table"
            print "2: 2 <username> - Start New Conversation with 'username'"
            print "3: 3 <username> <message> - Send 'message' to 'username'"


    def print_user_table(self):
        usernames = sorted(self.user_table.keys())
        for i in username:
            print "\t", i

    def subscribe(self):
        self.rsa = RSA.generate(2048)
        self.pub = self.rsa.exportKey()
        args = {"Type": "Subscribe", 
                "PublicKey": self.pub,
                "Username": self.username}
        print self.rsa, pub
        
        success = False
        while !success:
            r = send_request(args)
            if r['status'] == ERR_INVALID_USERNAME:
                print "Username is taken, please try again"
                sys.exit(0)
            if r['status'] == SUCCESS:
                self.user_id = r['user_id']
                self.last_id_seen = r['last_id_seen']
        return

    def client_update(self):
        while True:
            args = {"Type": "ClientUpdate", 
                    "LastIdSeen": self.last_id_seen}
            r = send_request(args)
            if r['status'] == SUCCESS:
                if r['new_client'] == TRUE:
                    data = r['new_client_data']    
                    self.user_table = User(data['username'],data['user_id'],data['public_key'])
                    self.last_id_seen += 1
                    time.sleep(NEW_CLIENT_WAIT_SHORT)
                    continue
            else r['status'] == FAILED:
                print "ERROR: Client Update failed"

            time.sleep(NEW_CLIENT_WAIT)
    	return

    def init_conversation(self, username):

        # Reserve Read/Write blocks
        while True:
            args = {"Type": "ReserveSlot"}


        args = {"Type": "InitConversation",
                "Username": username}

    	pass

    def conversation_update(self):
    	pass

    def send_message(self, username, message):
        pass

    def read_message(signature, ciphertext, other_user_public_key, my_key): #assumes other_user_public_key is tuple of form (n,e), my_key is of form (n,e,d)
        checksum_n = other_user_public_key[0]
        checksum_e = other_user_public_key[1]
        n = my_key[0]
        e = my_key[1]
        d = my_key[2]
        plaintext = RSA_decrypt(ciphertext, n, e, d)
        if PKCS1_verify(signature, plaintext, checksum_n, checksum_e) != True:
            return 'Message could not be verified'
        return plaintext

    def collect_messages(self):
    	pass

def send_request(args, reply):
    r = requests.get(SERVER_URL, params=args)
    if(r.status_code != 200):
        raise Exception(r.text)
    return r.text.splitlines()


def gen_rsa():
    return RSA.generate(2048)

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

if len(sys.argv) < 2:
    print "ERROR: Please start client with an input username"
    sys.exit(0)

client = Client()
username_in = sys.argv[1]
client.main(username_in)
 