from flask import current_app as app

def verify(nonce, signature):
    n, d = app.jinja_env.globals['server_sk']
    return power(nonce, d, n) == signature

def deletion_verify(nonce, signature, slot_id):
    if not verify(nonce, signature):
        return False
    return (nonce >> 128) == slot_id 

def ust_sign(blinded_nonce):
    n, d = app.jinja_env.globals['server_sk']
    return power(blinded_nonce, d, n)

def power(x, y, z):
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

