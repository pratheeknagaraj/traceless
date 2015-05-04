from flask import current_app

def verify(nonce, signature):
    n, d = app.jinja_env.globals['server_sk']
    return (nonce ** d) % n == signature

def deletion_verify(nonce, signature, slot_id):
    if not verify(nonce, signature):
        return False
    return (nonce >> 128) == slot_id 

def ust_sign(blinded_nonce):
    n, d = app.jinja_env.globals['server_sk']
    return (blinded_nonce ** d) % n
