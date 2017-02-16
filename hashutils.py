
#####################################################
#
# hashutils
#
# A handful of hashing utility functions
# to help us encrypt and decrypt sensitive user info
#
#####################################################

import hmac
import hashlib
import random
import string


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def valid_pw(pw, h):
    """
    pw: came in from the user, just now
    h: came from the db, by looking up that username
    """
    salt = h.split(',')[-1]
    return make_pw_hash(pw, salt) == h


def make_pw_hash(pw, salt=None):
    if salt is None:
        salt = make_salt()
    h = hashlib.pbkdf2_hmac('sha256', pw, salt, iterations=100000)
    return h + ',' + salt

# --- that's it for passwords
# the rest is for usernames

# Please set "username: ahamilton" as your cookie
# (pass it along on every future request)
# THAT's NOT SECURE!!

# {username: ahamilton, expires_on: "2017-02-14"}|hash(<---)
# data|signature
# data|hash(data + SECRET)
# to verify, we can split on |,
# hash(data + secret), check if it's equal to
# the signature
SECRET = 'czUv86iAN9GXA3MT'
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return s + '|' + hash_str(s)

def check_secure_val(h):
    s = h.split('|')[0]
    if h == make_secure_val(s):
        return s
    return None
