# -*- coding: utf-8 -*-

"""Main module."""
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import pickle
import base64
import os
import weakref
from getpass import getpass
import wrapt

class Fernet(Fernet):
    def __reduce__(self):
        key = self._signing_key+self._encryption_key
        return(Fernet,(key,))

def keyFromPassword(password,salt=None):
    password = password.encode()
    if not salt:
        salt = os.environ.get('XONSH_SALT',os.environ.get('USER','no-set-salt'))
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(salt.encode())
    salt = digest.finalize()
    salt = salt[:16]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    keyStr = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(keyStr)

def initPasswordProtectedKey(helpText=True):
    p1 = getpass('Enter the new password: ')
    p2 = getpass('Confirm your password : ')
    assert p1 == p2
    passwordKey = keyFromPassword(p1)
    token = Fernet.generate_key()
    key = Fernet(token)
    dataStr = passwordKey.encrypt(pickle.dumps(key))
    dataStr = base64.urlsafe_b64encode(dataStr)
    if helpText:
        print("You can lock a new object with lockedobjects.lockObject(obj)")
        print("Add the following to ~/.xonshrc")
        print("from lockedobject import LockedObject, passwordPrompt")
        print("$ENV_KEY=LockedObject({} , passwordPrompt)".format(dataStr))
        print("$SECRET_VALUE=LockedObject('lockedObjectString' , $ENV_KEY)".format(dataStr))
    return (key,dataStr)

def lockObject(obj,key=None):
    if not key:
        key=os.environ['ENV_KEY'].decrypt()
    return base64.urlsafe_b64encode(key.encrypt(pickle.dumps(obj)))

passwordPrompt = lambda: keyFromPassword(getpass("Enter password to unlock locked variables: "))

class LockedObject(wrapt.ObjectProxy):
    def __init__(self, dataStr, keyFunc, cached=False):
        self.encData=base64.urlsafe_b64decode(dataStr)
        self.keyFunc=keyFunc
        self.cached=cached
        self.cachedData=lambda: None

    def decrypt(self):
        if self.cachedData() != None:
            return self.cachedData()
        key = self.keyFunc()
        data = pickle.loads(key.decrypt(self.encData))
        if self.cached:
            self.cachedData=lambda: data
        else:
            self.cachedData=weakref.ref(data)
        return data

    def purge(self):
        obj = self.cachedData()
        del obj
        self.cachedData=lambda: None

    def __str__(self):
        return str(self.decrypt())
