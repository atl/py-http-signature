import base64

from Crypto.Hash import SHA256, SHA, SHA512, HMAC
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

HASHES = {'sha256': SHA256,
          'sha1':   SHA,
          'sha512': SHA512}

class Signer(object):
    def __init__(self, secret='', algorithm='rsa-sha256'):
        self.sign_algorithm, self.hash_algorithm = algorithm.split('-')
        if self.sign_algorithm == 'rsa':
            with open(secret) as fh:
                rsa_key = RSA.importKey(fh.read())
            self._rsa = PKCS1_v1_5.new(rsa_key)
            self._hash = HASHES[self.hash_algorithm]
        elif self.sign_algorithm == 'hmac':
            self._hash = HMAC.new(secret, digestmod=HASHES[self.hash_algorithm])
            self._rsa = False
    
    def sign_rsa(self, sign_string):
        h = self._hash.new()
        h.update(sign_string)
        return self._rsa.sign(h)
    
    def sign_hmac(self, sign_string):
        hmac = self._hash.copy()
        hmac.update(sign_string)
        return hmac.digest()
    
    def sign(self, sign_string):
        if self._rsa:
            data = self.sign_rsa(sign_string)
        else:
            data = self.sign_hmac(sign_string)
        return base64.b64encode(data)
    
