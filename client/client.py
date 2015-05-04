import hashlib
import random
import requests
import sys
import time
import thread
import json

from util import *
from UST import *

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto import Random

# Server Data
SERVER_URL = 'http://localhost:5000'

# Errors
ERROR = "Error"

# Constants
SUCCESS = "Success"
FAILED = "Failed"
TRUE = "True"
FALSE = "False"

# Routes
SERVER                          = 'server'
SUBSCRIBE                       = 'subscribe'
PUSH                            = 'push'
PULL                            = 'pull'
UPDATE_USER_TABLE               = 'update_user_table'
UPDATE_NEW_CONVERSATION_TABLE   = 'update_new_conversation_table'
INITIATE                        = 'initiate'
DELETE                          = 'delete'
RESERVE                         = 'reserve'

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
        self.connect_server()
        self.subscribe()

        # Upon successfully suscribing begin updates
        self.updates()

    def connect_server(self):
        r = send_request(SERVER, {})
        self.server_pk_n = r['server_pk_n']
        self.server_pk_e = r['server_pk_e']

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
        self.rsa = RSA_gen()
        self.n, self.e, self.d = RSA_keys(self.rsa)

        self.rsa_sign = RSA_gen()
        self.n_sign, self.e_sign, self.d_sign = RSA_keys(self.rsa_sign)

        self.ust = UST(self.server_pk_n, self.server_pk_e)

        args = {"blinded_nonce":    self.ust.blinded_nonce, 
                "client_username":  self.username,
                "client_pk_n":      self.n, 
                "client_pk_e":      self.e,
                "client_sign_pk_n": self.n_sign,
                "client_sign_pk_e": self.e_sign}
        print self.rsa, pub
        
        success = False
        while not success:
            r = send_request(SUBSCRIBE, args)
            if r == ERROR:
                print "Username is taken, please try again"
                sys.exit(0)
                blinded_sign = r['blinded_sign']
                user = r['user']
                self.server_pk = r['server_pk']
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
            elif r['status'] == FAILED:
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
        if PKCS1_verify(signature, message, checksum_n, checksum_e) != True:
            return 'Message could not be verified'
        n = my_key[0]
        e = my_key[1]
        d = my_key[2]
        plaintext = RSA_decrypt(ciphertext, n, e, d)
        return plaintext

    def collect_messages(self):
    	pass

    def ust_update():
        new_nonce = random.getrandbits(2048)
        blinded_new_hash



def send_request(route, args):
    response = requests.post(SERVER_URL + "/" + route, data=json.dumps(args))
    if(response.status_code != 200):
        raise Exception(response.text)
        return ERROR
    return response.text

def RSA_gen():
    return RSA.generate(2048)

def RSA_keys(rsa):
    return rsa.n, rsa.e, rsa.d #returns RSA key object, n, e (both public) and secret key d

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

def H(m):
    """
   return hash (256-bit integer) of string m, as long integer.
   If the input is an integer, treat it as a string.
   """
    m = str(m)
    return int(hashlib.sha256(m).hexdigest(),16)

#if len(sys.argv) < 2:
#    print "ERROR: Please start client with an input username"
#    sys.exit(0)

#client = Client()
#username_in = sys.argv[1]
#client.main(username_in)
 