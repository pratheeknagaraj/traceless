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

from bitarray import *
from multiprocessing.pool import ThreadPool
from ast import literal_eval

from UST import *
from user import *
from conversation import *
from server import *

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import GCD

# Master URL
MASTER_URL = 'http://localhost:5000'

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
UPDATE_SERVER_VIEW              = 'update_server_view'
INITIATE                        = 'initiate'
DELETE                          = 'delete'
RESERVE                         = 'reserve'
CONNECT_TO_SLAVE                = 'connect_to_slave'


# Wait Times
NEW_CLIENT_WAIT         = 3.000     # Wait 3 seconds
NEW_CONVERSATION_WAIT   = 3.000     # Wait 3 second
NEW_MESSAGE_WAIT        = 1.000     # Wait 1 second
SERVER_UPDATE_WAIT      = 5.000     # Wait 5 seconds

class Client:

    def main(self,username):

        self.server_table = {}
        self.shard_table = {}
        self.ust_table = {}
        self.user_table = {}
        self.conversations = {}
        self.conversation_lock = threading.Lock()

        self.rsa = None
        self.rsa_sign = None

        self.username = username
        self.connect_server()
        self.subscribe()

        # Upon successfully suscribing begin updates
        self.updates()

        self.client_input()

    def connect_server(self):
        r = send_request(MASTER_URL, SERVER, {})
        n = r['server_pk_n']
        e = r['server_pk_e']
        self.server_table = {MASTER_URL: Server(MASTER_URL, n, e)}

    def updates(self):
        try:
            thread.start_new_thread(self.client_update, ())
            thread.start_new_thread(self.conversation_update, ())
            thread.start_new_thread(self.message_update, ())
            thread.start_new_thread(self.server_update, ())
        except:
            print "ERRROR: unable to start client threads"
            print "FATAL: client unable to update"
            sys.exit(0)

    def client_input(self):
        while True:
            cmd = raw_input("[Please enter your next command]\n>> ")
            self.handle_input(cmd)

    def handle_input(self, cmd):
        parts = cmd.split(' ', 1)
        cmd_type = parts[0]

        if cmd_type == "1" or cmd_type == "ut":
            self.print_user_table() 
        elif cmd_type == "2" or cmd_type == "ct":
            self.print_conversation_table()
        elif cmd_type == "3" or cmd_type == "c":
            cmd_args = parts[1]
            self.init_conversation(cmd_args)
        elif cmd_type == "4" or cmd_type == "m":
            cmd_args = parts[1]
            split = cmd_args.split(' ', 1)
            username = split[0]
            message = split[1] 
            self.send_message(username, message)
        elif cmd_type == "H":
            print "  1: [1,ut] - Print Local User Table"
            print "  2: [2,ct] - Print Local Conversation Table"
            print "  3: [3,c] <username> - Start Conversation with 'username'"
            print "  4: [4,m] <username> <message> - Send 'message' to 'username'"

    def print_user_table(self): 
        print "=== Local User Table ==="
        usernames = sorted(self.user_table.keys())
        for username in usernames:
            print "  %-24s" % username
        print "\n",

    def print_conversation_table(self):
        print "=== Local Conversation Table ==="
        recipients = sorted(self.conversations.keys())
        for recipient in recipients:
            print "  %-24s" % recipients
        print "\n",

    def print_conversation(self,username):
        pass

    def gen_keys(self):
        self.rsa = RSA_gen(4096)
        self.n, self.e, self.d = RSA_keys(self.rsa)

        self.rsa_sign = RSA_gen(1024)
        self.n_sign, self.e_sign, self.d_sign = RSA_keys(self.rsa_sign)

    def subscribe(self):
        print "Subscribing please wait..."
        self.gen_keys()

        self.ust_table[MASTER_URL] = UST(self.server_table[MASTER_URL])

        ust = self.ust_table[MASTER_URL]
        ust.lock.acquire()
        ust.prepare()

        args = {"blinded_nonce"     :  ust.blinded_nonce, 
                "client_username"   :  self.username,
                "client_pk_n"       :  self.n, 
                "client_pk_e"       :  self.e,
                "client_sign_pk_n"  :  self.n_sign,
                "client_sign_pk_e"  :  self.e_sign}
        
        r = send_request(MASTER_URL, SUBSCRIBE, args)

        if r == ERROR:
            print "ERROR: could not subscribe"
            sys.exit(0)

        ust.receive(r['blinded_sign'])
        ust.lock.release()

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
        self.conversations_table_ptr = 0

        return

    def server_update(self):
        while True:
            ust = self.ust_table[MASTER_URL]
            ust.lock.acquire()
            ust.prepare()

            args = {"nonce"                     :  ust.nonce,
                    "signature"                 :  ust.signature,
                    "blinded_nonce"             :  ust.blinded_nonce}

            r = send_request(MASTER_URL, UPDATE_SERVER_VIEW, args)

            ust.receive(r['blinded_sign'])
            ust.lock.release()

            shards = r['shards']

            for shard_name, server_data in shards.items():

                shard_range = literal_eval(shard_name)

                if server_data == None:                                     # Shard no longer maps to a server
                    if shard_range in self.shard_table:
                        del self.shard_table[shard_range]
                        continue

                server = Server(server_data['url'], server_data['server_pk_n'], server_data['server_pk_e'])

                if shard_range not in self.shard_table:                     # Shard is new
                    self.shard_table[shard_range] = server
                    self.add_new_server(server)
                elif self.shard_table[shard_range].equal(server) == False:  # New server is resposible for this shard
                    self.shard_table[shard_range] = server
                    self.add_new_server(server)
            
            time.sleep(SERVER_UPDATE_WAIT)
        return

    def add_new_server(self, server):
        # Check if the server table does not have identifcal server under url
        if server.url in self.server_table:
            if self.server_table[server.url].equals(server):
                return

        self.server_table[server.url] = server
        slave_ust = UST(self.server_table[server.url])
        slave_ust.lock.acquire()
        slave_ust.prepare()

        ust = self.ust_table[MASTER_URL]
        ust.lock.acquire()
        ust.prepare()

        args = {"nonce"                 :  ust.nonce,
                "signature"             :  ust.signature,
                "blinded_nonce"         :  ust.blinded_nonce, 
                "blinded_slave_nonce"   :  slave_ust.blinded_nonce,
                "slave_url"             :  server.url}

        r = send_request(MASTER_URL, CONNECT_TO_SLAVE, args)

        ust.receive(r['blinded_sign'])
        ust.lock.release()

        slave_ust.receive(r['blinded_slave_sign'])
        slave_ust.lock.release()

    def client_update(self):
        while True:
            ust = self.ust_table[MASTER_URL]
            ust.lock.acquire()
            ust.prepare()

            args = {"nonce"                 :  ust.nonce,
                    "signature"             :  ust.signature,
                    "blinded_nonce"         :  ust.blinded_nonce, 
                    "client_user_table_ptr" :  self.user_table_ptr}

            r = send_request(MASTER_URL, UPDATE_USER_TABLE, args)
            
            ust.receive(r['blinded_sign'])
            ust.lock.release()

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
            # Consider who to resever from, master is default
            ust = self.ust_table[MASTER_URL]
            ust.lock.acquire()
            ust.prepare()

            slot_id = random.getrandbits(128) 
            delete_nonce = (slot_id << 128) + random.getrandbits(128)
            ust_delete = UST(self.server_table[MASTER_URL])
            ust_delete.prepare(delete_nonce)

            args = {"nonce"                     :  ust.nonce,
                    "signature"                 :  ust.signature,
                    "blinded_nonce"             :  ust.blinded_nonce, 
                    "slot_id"                   :  slot_id,
                    "blinded_deletion_nonce"    :  ust_delete.blinded_nonce}

            r = send_request(MASTER_URL, RESERVE, args)

            ust.receive(r['blinded_sign'])
            ust.lock.release()

            if r['success'] == True:
                ust_delete.receive(r['blinded_deletion_sign'])
                sig = ust_delete.signature
                return slot_id, delete_nonce, sig

    def reserve_slot_forced(self):
        slot_id = None

        while True:
            slot_id = random.getrandbits(128) 
            if self.get_shard_from_slot(slot_id)[0]:
                break

        return slot_id, None, None

    def get_shard_from_slot(self, slot_id):
        for shard in self.shard_table:
            if self.slot_in_shard(slot_id, shard):
                return True, shard
        return False, None

    def slot_in_shard(self, slot_id, shard):
        if shard[0] <= slot_id < shard[1]:
            return True
        return False

    def init_conversation(self, recipient):
        if recipient == self.username:
            print "ERROR: Please enter a username that is not your own"
            return 

        # Reserve Read/Write slot
        read_slot_id, read_nonce, read_slot_sig = self.reserve_slot_forced()
        write_slot_id, write_nonce, write_slot_sig = self.reserve_slot_forced()

        x = bin(int(binascii.hexlify(self.username), 16))
        my_username = x.ljust(256)

        y = bin(int(binascii.hexlify(recipient), 16))
        recipient_username = y.ljust(256)

        P = (int(my_username, 2) << 512) +  \
            (int(recipient_username,2) << 256) + \
            (read_slot_id << 128) + \
            write_slot_id

        sign = PKCS1_sign(str(P), self.rsa_sign)
        rsa_recipient = RSA_gen_user(self.user_table[recipient])
        sign_enc = RSA_encrypt(sign, rsa_recipient)
        P_enc = RSA_encrypt(str(P), rsa_recipient)
        enc_M = sign_enc + "*****" + P_enc
        
        ust = self.ust_table[MASTER_URL]
        ust.lock.acquire()
        ust.prepare()
        
        args = {"nonce"                     :  ust.nonce,
                "signature"                 :  ust.signature,
                "blinded_nonce"             :  ust.blinded_nonce, 
                "message"                   :  enc_M}

        r = send_request(MASTER_URL, INITIATE, args)
        ust.receive(r['blinded_sign'])
        ust.lock.release()

        conversation_obj = Conversation(self.user_table[self.username],
                                        self.user_table[recipient],
                                        read_slot_id,
                                        write_slot_id)

        self.conversation_lock.acquire()
        self.conversations[recipient] = conversation_obj
        self.conversation_lock.release()

        return 

    def conversation_update(self):

        while True:
            ust = self.ust_table[MASTER_URL]
            ust.lock.acquire()
            ust.prepare()

            args = {"nonce"                              :  ust.nonce,
                    "signature"                          :  ust.signature,
                    "blinded_nonce"                      :  ust.blinded_nonce, 
                    "client_new_conversations_table_ptr" :  self.conversations_table_ptr}

            r = send_request(MASTER_URL, UPDATE_NEW_CONVERSATION_TABLE, args)
            
            ust.receive(r['blinded_sign'])
            ust.lock.release()

            new_conversations = r['new_conversations']

            for conversation in new_conversations:
                conversation_id = conversation['conversation_id']

                enc_M = conversation['message']

                self.conversations_table_ptr = conversation_id + 1
                ciphertext = enc_M.split("*****")
                sign = RSA_decrypt(ciphertext[0], self.rsa)
                P = RSA_decrypt(ciphertext[1], self.rsa)

                try:
                    b = bin(int(P))[2:] 
                    b2 = (768-len(b))*'0' + b
                    sender = (''.join(chr(int(b2[i:i+8], 2)) for i in xrange(0, 256, 8))).replace('\x00','')
                    recipient = (''.join(chr(int(b2[i:i+8], 2)) for i in xrange(256, 512, 8))).replace('\x00','')
                    write_slot_id = int(b2[512:640],2)
                    read_slot_id = int(b2[640:],2)

                    if recipient != self.username:
                        continue

                    rsa_sign_sender = RSA_gen_user_sign(self.user_table[sender])

                    # TODO, fix verification, assume no spoofs atm
                    # if PKCS1_verify(sign, str(P), rsa_sign_sender):
                    #    print "VERIFIED!", recipient
                    conversation_obj = Conversation(self.user_table[self.username],
                                                    self.user_table[sender],
                                                    read_slot_id,
                                                    write_slot_id)
       
                    self.conversation_lock.acquire()
                    self.conversations[sender] = conversation_obj
                    self.conversation_lock.release()
                    print "\nConversation started with: ", sender, "\n>> ",
                except:
                    continue

            time.sleep(NEW_CONVERSATION_WAIT)
        return

    def shards_available():
        if len(self.shard_table) == 0:
            return False
        return True

    def get_slave_from_slot(self, slot_id):
        ok, shard = self.get_shard_from_slot(slot_id)
        if not ok:
            return False
        return shard.url

    def send_message(self, username, text): #, slot_id, next_block, ND, ND_signed):
        if len(text) > 256:
            print "\nERROR: message too long\n>> ",
            return

        if username not in self.user_table:
            print "\nERROR: user " + username + " does not exist\n>> ",
            return

        if username not in self.conversations:
            print "\nERROR: please start conversation with " + username + " first\n>> ",
            return

        if not self.shards_available():
            print "\nERROR: server cannot accept messages at this time\n>> ",
            return 

        conversation = self.conversations[username]
        write_slot_id = conversation.write_slot_id

        new_write_slot_id, new_write_nonce, new_write_slot_sig = self.reserve_slot_forced()

        conversation.update_write_slot(new_write_slot_id)

        msg = text.ljust(128)
        x = bin(int(binascii.hexlify(msg), 16))
        new_text = int(x,2)
        
        #P = (new_text << 2432) + (next_block << 2304) + (ND << 2048) + (ND_signed)
        
        P = (new_text << 128) + new_write_slot_id  

        signature = PKCS1_sign(str(P), self.rsa_sign)
        recipient = self.user_table[username]
        rsa_recipient = RSA_gen_user(recipient)

        ciphertext = RSA_encrypt(signature, rsa_recipient) + \
                     "*****" + RSA_encrypt(str(P), rsa_recipient)

        slave_url = self.get_slave_from_slot(write_slot_id)
        if slave_url == False:
            print "\nERROR: server cannot accept messages at this time\n>> ",
            return 

        ust = self.ust_table[slave_url]
        ust.lock.acquire()
        ust.prepare()

        args = {"nonce"                     :  ust.nonce,
                "signature"                 :  ust.signature,
                "blinded_nonce"             :  ust.blinded_nonce,
                "slot_id"                   :  write_slot_id,
                "message"                   :  ciphertext}

        r = send_request(slave_url, PUSH, args)

        ust.receive(r['blinded_sign'])
        ust.lock.release()

        conversation.add_write_text(text)
        print "\n" + conversation.get_conversation() + "\n>> ",
        return

    def message_update(self):
        while True:
            for sender, conversation in self.conversations.items():
                read_slot_id = conversation.read_slot_id

                slave_url = self.get_slave_from_slot(read_slot_id)
                if slave_url == False:
                    continue 

                ust = self.ust_table[slave_url]
                ust.lock.acquire()
                ust.prepare()

                args = {"nonce"              :  ust.nonce,
                        "signature"          :  ust.signature,
                        "blinded_nonce"      :  ust.blinded_nonce, 
                        "slot_id"            :  read_slot_id}

                r = send_request(slave_url, PULL, args)
                
                ust.receive(r['blinded_sign'])
                ust.lock.release()

                messages = r['messages']

                for message in messages:
                    
                    try:
                        ciphertext = message.split("*****")
                        sign = RSA_decrypt(ciphertext[0], self.rsa)
                        P = RSA_decrypt(ciphertext[1], self.rsa)

                        b = bin(int(P))[2:]

                        new_read_slot_id = int(b[-128:],2)
                        rest = '0' + str(b[:-128])          # Yeah... don't worry about this...
                        text = (''.join(chr(int(rest[i:i+8], 2)) for i in xrange(0, len(rest), 8))).strip()
                        # Need to verify message sender
                        # Can use just username

                        conversation.update_read_slot(new_read_slot_id)
                        conversation.add_read_text(text)
                        print "\n" + conversation.get_conversation() + "\n>> ",
                    except:
                        continue

            time.sleep(NEW_MESSAGE_WAIT)
        return

def send_request(server, route, args, retry=True):
    RETRY_TICKS = 100

    # if 'nonce' in args:
    #     print args['nonce'] % 10000, route, server

    headers = {'content-type': 'application/json'}
    data = json.dumps(args)
    url = server + "/" + route
    pool = ThreadPool(processes=1)
    response_handle = pool.apply_async(send, (url, headers, data)) 

    # Handle Timeouts
    ticks = 0
    while True:
        ok = response_handle.ready()
        if not ok:
            ticks += 1
            if retry and ticks > RETRY_TICKS:
                pool.terminate()
                pool = ThreadPool(processes=1)
                response_handle = pool.apply_async(send, (url, headers, data)) 
                ticks = 0
            else:
                time.sleep(0.01)
        else:
            break

    response = response_handle.get()

    if not (200 <= response.status_code < 300):
        raise Exception(response.text)
        return ERROR
    return json.loads(response.text)

# ===== Do Not Change ======
# Simulate successful or dropped packet
UNRELIABLE = False
def send(url, headers, data):
    DROP_RATE = 0.01
    if UNRELIABLE and random.random() < DROP_RATE:
        while True:
            # The world keeps spinning
            pass

    response = requests.post(url, headers=headers, data=data)
    return response

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



if len(sys.argv) < 2:
    print "ERROR: Please start client with an input username"
    sys.exit(0)

client = Client()
username_in = sys.argv[1]
client.main(username_in)
