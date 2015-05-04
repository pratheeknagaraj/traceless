class User:

    def __init__(self,username,user_id,pk_n,pk_e,pk_sign_n,pk_sign_e):
        self.username = username
        self.user_id = user_id
        self.pk_n = pk_n
        self.pk_e = pk_e
        self.pk_sign_n = pk_sign_n
        self.pk_sign_e = pk_sign_e

    def __str__(self):
        return self.username

    def __repr__(self):
        return self.username 