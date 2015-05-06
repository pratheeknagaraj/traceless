import hashlib
import random
import requests
import sys
import time
import thread
import json
import binascii
import math
import base64
import threading
import bitarray

from UST import *
from user import *
from conversation import *

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import GCD

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
UPDATE_NEW_CONVERSATION_TABLE   = 'update_new_conversations_table'
INITIATE                        = 'initiate'
DELETE                          = 'delete'
RESERVE                         = 'reserve'

# Wait Times
NEW_CLIENT_WAIT         = 3.000     # Wait 3 seconds
NEW_CONVERSATION_WAIT   = 3.000     # Wait 1 second

class Client:

    def main(self,username):

        self.user_table = {}
        self.conversations = {}
        self.conversation_lock = threading.Lock()
        self.ust = None
        self.ust_lock = threading.Lock()

        self.rsa = None
        self.rsa_sign = None

        self.username = username
        self.connect_server()
        self.subscribe()

        # Upon successfully suscribing begin updates
        self.updates()

        self.client_input()

    def connect_server(self):
        r = send_request(SERVER, {})
        self.server_pk_n = r['server_pk_n']
        self.server_pk_e = r['server_pk_e']

    def updates(self):
        try:
            thread.start_new_thread(self.client_update, ())
            thread.start_new_thread(self.conversation_update, ())
        except:
            print "ERRROR: unable to start client threads"
            print "FATAL: client unable to update"
            sys.exit(0)

    def client_input(self):
        while True:
            cmd = raw_input("Please enter a command: ")
            self.handle_input(cmd)

    def handle_input(self, cmd):
        parts = cmd.split(' ', 1)
        cmd_type = parts[0]

        if cmd_type == "1":
            self.print_user_table() 
        elif cmd_type == "2":
            cmd_args = parts[1]
            self.init_conversation(cmd_args)
        elif cmd_type == "3":
            cmd_args = parts[1]
            split = cmd_args.split(' ', 1)
            username = split[0]
            message = split[1] 
            self.send_message(username, message)
        elif cmd_type == "H":
            print "  1: 1 - Print Local User Table"
            print "  2: 2 <username> - Start Conversation with 'username'"
            print "  3: 3 <username> <message> - Send 'message' to 'username'"


    def print_user_table(self): 
        print "=== Local User Table ==="
        usernames = sorted(self.user_table.keys())
        for username in usernames:
            print "  %-24s" % username
        print "\n",

    def subscribe(self):
        print "Subscribing please wait..."
        self.rsa = RSA_gen(4096)
        self.n, self.e, self.d = RSA_keys(self.rsa)
        #self.ElGkey = ElGamal.generate(256, Random.new().read)

        self.rsa_sign = RSA_gen(1024)
        self.n_sign, self.e_sign, self.d_sign = RSA_keys(self.rsa_sign)

        self.ust = UST(self.server_pk_n, self.server_pk_e)
        self.ust_lock.acquire()
        self.ust.prepare()

        args = {"blinded_nonce"     :  self.ust.blinded_nonce, 
                "client_username"   :  self.username,
                "client_pk_n"       :  self.n, 
                "client_pk_e"       :  self.e,
                "client_sign_pk_n"  :  self.n_sign,
                "client_sign_pk_e"  :  self.e_sign}
        
        r = send_request(SUBSCRIBE, args)

        if r == ERROR:
            print "ERROR: could not subscribe"
            sys.exit(0)

        self.ust.receive(r['blinded_sign'])
        self.ust_lock.release()

        user = r['user']

        if user['client_pk_n'] == self.n and user['client_pk_e'] == self.e \
            and user['client_sign_pk_n'] == self.n_sign \
            and user['client_sign_pk_e'] == self.e_sign:
            pass
        else:
            print "Username is taken, please try again"
            sys.exit(0)

        self.user_id = user['client_user_id']
        self.user_table_ptr = 0
        self.client_new_conversations_table_ptr = 0

        return

    def client_update(self):
        while True:
            self.ust_lock.acquire()
            self.ust.prepare()

            args = {"nonce"                 :  self.ust.nonce,
                    "signature"             :  self.ust.signature,
                    "blinded_nonce"         :  self.ust.blinded_nonce, 
                    "client_user_table_ptr" :  self.user_table_ptr}

            r = send_request(UPDATE_USER_TABLE, args)
            
            self.ust.receive(r['blinded_sign'])
            self.ust_lock.release()

            new_users = r['new_users']

            for new_user in new_users:
                username = new_user['client_username']
                if username not in self.user_table:
                    user_id = new_user['client_user_id']
                    pk_n, pk_e, pk_sign_n, pk_sign_e = (new_user['client_pk_n'],
                                                       new_user['client_pk_e'],
                                                       new_user['client_sign_pk_n'],
                                                       new_user['client_sign_pk_e'])
                    user = User(username,user_id,pk_n,pk_e,pk_sign_n,pk_sign_e)
                    self.user_table[username] = user

                    self.user_table_ptr = user_id

            time.sleep(NEW_CLIENT_WAIT)
    	return

    def reserve_slot(self):
        while True:
            self.ust_lock.acquire()
            self.ust.prepare()

            slot_id = random.getrandbits(128) 
            delete_nonce = (slot_id << 128) + random.getrandbits(128)
            ust_delete = UST(self.server_pk_n,self.server_pk_e)
            ust_delete.prepare(delete_nonce)

            args = {"nonce"                     :  self.ust.nonce,
                    "signature"                 :  self.ust.signature,
                    "blinded_nonce"             :  self.ust.blinded_nonce, 
                    "slot_id"                   :  slot_id,
                    "blinded_deletion_nonce"    :  ust_delete.blinded_nonce}

            r = send_request(RESERVE, args)

            self.ust.receive(r['blinded_sign'])
            self.ust_lock.release()

            if r['success'] == True:
                ust_delete.receive(r['blinded_deletion_sign'])
                sig = ust_delete.signature
                return slot_id, delete_nonce, sig

    def init_conversation(self, recipient):
        if recipient == self.username:
            print "ERROR: Please enter a username that is not your own"

        # Reserve Read/Write slot
        read_slot_id, read_nonce, read_slot_sig = self.reserve_slot()
        write_slot_id, write_nonce, write_slot_sig = self.reserve_slot()


        my_username = int(bin(int(binascii.hexlify(self.username.ljust(256)), 16)),2)
        recipient_username = int(bin(int(binascii.hexlify(recipient.ljust(256)), 16)),2)

        P = (write_slot_sig << 1024) + \
            (write_nonce << 768) + \
            (my_username << 512) +  \
            (recipient_username << 256) + \
            (read_slot_id << 128) + \
            write_slot_id
        
        sign = PKCS1_sign(str(P), self.rsa_sign)
        M = sign + P
        #print sign.strip(), P, type(sign), type(P)

        rsa_recipient = RSA_gen_user(self.user_table[recipient])
        enc_M = RSA_encrypt( M, rsa_recipient)
 
        self.ust_lock.acquire()
        self.ust.prepare()
        
        args = {"nonce"                     :  self.ust.nonce,
                "signature"                 :  self.ust.signature,
                "blinded_nonce"             :  self.ust.blinded_nonce, 
                "message"                   :  enc_M}

        r = send_request(INITIATE, args)
        self.ust.receive(r['blinded_sign'])
        self.ust_lock.release()

        conversation_obj = Conversation(self.user_table[self.username],
                                        self.user_table[recipient],
                                        read_slot_id,
                                        write_slot_id,
                                        read_nonce,
                                        read_slot_sig)


        self.conversation_lock.acquire()
        self.conversations[recipient] = conversation_obj
        self.conversation_lock.release()

        return 

    def conversation_update(self):

        while True:
            print "HERE NOW"
            self.ust_lock.acquire()
            self.ust.prepare()

            args = {"nonce"                              :  self.ust.nonce,
                    "signature"                          :  self.ust.signature,
                    "blinded_nonce"                      :  self.ust.blinded_nonce, 
                    "client_new_conversations_table_ptr" :  self.client_new_conversations_table_ptr}

            r = send_request(UPDATE_NEW_CONVERSATION_TABLE, args)
            
            self.ust.receive(r['blinded_sign'])
            self.ust_lock.release()

            new_conversations = r['new_conversations']

            print new_conversations
            for conversation in new_conversations:
                conversation_id = conversation['conversation_id']
                enc_M = conversation['message']

                self.client_new_conversations_table_ptr = conversation_id

                M = RSA_decrypt(enc_M, self.rsa)
                print "M: ", M
                parts = M.split("****")
                print "SPLITTED", parts
                if len(parts) != 2:
                    # Not a valid decryption,
                    # Message was not intended for me
                    continue

                print "BYTING"

                sign = str(parts[0])
                P = str(parts[1])

                bit_P = bitarray()
                bit_P.fromstring(P)

                write_slot_sig  = bit_P[0:1024].tobytes()
                write_nonce     = bit_P[1024:1280].tobytes()
                sender          = bit_P[1280:1536].tobytes()
                recipient       = bit_P[1536:1792].tobytes()
                write_slot_id   = bit_P[1792:1920].tobytes()
                read_slot_id    = bit_P[1920:2048].tobytes()

                print sender, recipient, write_slot_id, read_slot_id

                if recipient != self.username:
                    # Should not reach here
                    # otherwise continue since this is not for us
                    continue

                # First verify this is actually from sender
                rsa_sign_sender = RSA_gen_user_sign(self.user_table[sender])

                if PKCS1_verify(sign, P, rsa_sign_sender):
                
                    conversation_obj = Conversation(self.user_table[username],
                                                    self.user_table[sender],
                                                    read_slot_id,
                                                    write_slot_id)

                    while self.conversation_lock:
                        continue
                    self.conversation_lock.acquire()
                    self.conversations[sender] = conversation_obj
                    self.conversation_lock.release()

            time.sleep(NEW_CONVERSATION_WAIT)
        return

    def send_message(self, username, text, slot_id, next_block, ND, ND_signed):
        if len(text) > 256:
            print "ERROR: message too long"
            return

        msg = text.ljust(256)
        x = bin(int(binascii.hexlify(msg), 16))
        new_text = int(x,2)
        P = (new_text << 2432) + (next_block << 2304) + (ND << 2048) + (ND_signed)
        self.ust_lock.acquire()
        self.ust.prepare()
        # h = SHA.new()
        # h.update(str(P))
        # signer = PKCS1_PSS.new(self.rsa)
        # signature = signer.sign(h)
        signature = ElG_sign(P, self.ElGkey)
        cipher = signature + P
        other_user = self.user_table[username]
        rsa_key = RSA_gen_user(other_user)
        ciphertext = RSA_encrypt(cipher, rsa_key)
        args = {"nonce":    self.ust.nonce,
                "signature":    blinded_sign,
                "blinded_nonce":    self.ust.blinded_nonce,
                "slot_id":  slot_id,
                "message":  ciphertext}
        r = send_request(PUSH, args)


        # TODO... alot, receive, etc.

        if r['status'] == FAILED:
            print 'ERROR: could not push message'
        return

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

    def collect_messages(self, ciphertext, username): #assumes already pulled from server
        plaintext = RSA_decrypt(ciphertext, self.rsa)
        signature = plaintext >> 4480
        other_user = user['username']
        n = user.n_sign
        e = user.e_sign
        rsa_key = RSA.construct((n,e))
        if PKCS1_verify(signature, plaintext, rsa_key) != True:
            print "message could not be verified"
            return
        a = ciphertext - (signature << 4480)
        msg_retrieve = a >> 2432
        nb = (a >> 2304) - (msg_retrieve << 128)
        nd = (a >> 2048) - (msg_retrieve << 384) - (nb << 256)
        signed_nd = a - (msg_retrieve << 2432) - (nb_final << 2176) - (nd_temp << 2048)
        text = binascii.unhexlify('%x' % msg_retrieve)
    	return text, nb, nd, signed_nd


def send_request(route, args):
    headers = {'content-type': 'application/json'}
    response = requests.post(SERVER_URL + "/" + route, headers=headers, data=json.dumps(args))
    if not (200 <= response.status_code < 300):
        raise Exception(response.text)
        return ERROR
    return json.loads(response.text)

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

def ElG_sign(message,key):
    h = SHA.new(message).digest()
    while 1:
        k = Random.random.StrongRandom().randint(1,key.p-1)
        if GCD(k,key.p-1)==1: 
            break
    sig = key.sign(h,k)
    return sig

def H(m):
    """
   return hash (256-bit integer) of string m, as long integer.
   If the input is an integer, treat it as a string.
   """
    m = str(m)
    return int(hashlib.sha256(m).hexdigest(),16)
'''
if len(sys.argv) < 2:
    print "ERROR: Please start client with an input username"
    sys.exit(0)

client = Client()
username_in = sys.argv[1]
client.main(username_in)
'''