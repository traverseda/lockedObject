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

class Fernet(Fernet):
    """
    A modified fernet that pickles.
    """
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
        print("You can lock a new object with lockedobjects.lockObject(obj),")
        print("which will return a string suitable for use in a lockedobjects.LockedObject(str, keyFunc)")
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

class LockedObject():
    """
    This is a proxy object, wrapping *something*.
    What it's wrapping, we don't know.
    Call the obj.__self__decrypt() method and find out.
    """
    def __init__(self, dataStr, keyFunc, cached=False):
        self.__self__encData=base64.urlsafe_b64decode(dataStr)
        self.__self__keyFunc=keyFunc
        self.__self__cached=cached
        self.__self__cachedData=lambda: None

    def __getattr__(self,attr):
        return getattr(self.__self__decrypt(),attr)
    def __str__(self):
        return str(self.__self__decrypt())

    def __self__decrypt(self):
        #Use raw fernet object as keyfunc, without wrapping it
        #it a function that returns a key.
        if hasattr(self.__self__keyFunc,"decrypt"):
            key=self.__self__keyFunc
        else:
            key=self.__self__keyFunc()

        if self.__self__cachedData() != None:
            return self.__self__cachedData()
        key = self.__self__keyFunc()
        data = pickle.loads(key.decrypt(self.__self__encData))
        if self.__self__cached:
            self.__self__cachedData=lambda: data
        else:
            self.__self__cachedData=weakref.ref(data)
        return data

    def __self__purge(self):
        obj = self.__self__cachedData()
        del obj
        self.__self__cachedData=lambda: None
