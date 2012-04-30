from os.path import expanduser
import base64
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime

from Crypto.Hash import SHA256, SHA, SHA512, HMAC
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import ssh

from .utils import sig, is_rsa

ALGORITHMS = frozenset(['rsa-sha1', 'rsa-sha256', 'rsa-sha512', 'hmac-sha1', 'hmac-sha256', 'hmac-sha512'])
HASHES = {'sha256': SHA256,
          'sha1':   SHA,
          'sha512': SHA512}

class Signer(object):
    def __init__(self, secret='~/.ssh/id_rsa', algorithm='rsa-sha256', allow_agent=True):
        assert algorithm in ALGORITHMS, "Unknown algorithm"
        self._agent_key = False
        self.sign_algorithm, self.hash_algorithm = algorithm.split('-')
        if allow_agent:
            keys = ssh.Agent().get_keys()
            self._keys = filter(is_rsa, keys)
            if self._keys:
                self._agent_key = self._keys[0] 
                self._keys = self._keys[1:]
                self.sign_algorithm, self.hash_algorithm = ('rsa', 'sha1')
        if self.sign_algorithm == 'rsa':
            with open(expanduser(secret)) as fh:
                rsa_key = RSA.importKey(fh.read())
            self._rsa = PKCS1_v1_5.new(rsa_key)
            self._hash = HASHES[self.hash_algorithm]
        elif self.sign_algorithm == 'hmac':
            self._hash = HMAC.new(secret, digestmod=HASHES[self.hash_algorithm])
            self._rsa = False
    
    @property
    def algorithm(self):
        return '%s-%s' % (self.sign_algorithm, self.hash_algorithm)
    
    def sign_agent(self, sign_string):
        data = self._agent_key.sign_ssh_data(None, sign_string)
        return sig(data)
    
    def sign_rsa(self, sign_string):
        h = self._hash.new()
        h.update(sign_string)
        return self._rsa.sign(h)
    
    def sign_hmac(self, sign_string):
        hmac = self._hash.copy()
        hmac.update(sign_string)
        return hmac.digest()
    
    def sign(self, sign_string):
        if self._agent_key:
            data = self.sign_agent(sign_string)
        elif self._rsa:
            data = self.sign_rsa(sign_string)
        else:
            data = self.sign_hmac(sign_string)
        return base64.b64encode(data)
    

class HeaderSigner(object):
    '''
    Generic object that will sign headers as a dictionary using the http-signature scheme.
    https://github.com/joyent/node-http-signature/blob/master/http_signing.md
    
    key_id is the mandatory label indicating to the server which secret to use
    secret is the filename of a pem file in the case of rsa, a password string in the case of an hmac algorithm
    algorithm is one of the six specified algorithms
    headers is a list of http headers to be included in the signing string, defaulting to "Date" alone.
    '''
    def __init__(self, key_id='~/.ssh/id_rsa', secret='', algorithm='rsa-sha256',
            headers=None, allow_agent=True):
        self.signer = Signer(secret=secret, algorithm=algorithm, allow_agent=allow_agent)
        self.key_id = key_id
        self.headers = headers
        self.signature_string_head = self.build_header_content()
    
    def build_header_content(self):
        param_map = {'keyId': self.key_id, 
                     'algorithm': self.signer.algorithm}
        if self.headers:
            param_map['headers'] = ' '.join(self.headers)
        kv = map('{0[0]}="{0[1]}"'.format, param_map.items())
        kv_string = ','.join(kv)
        sig_string = 'Signature {0} %s'.format(kv_string)
        return sig_string
    
    def sign(self, h):
        header_dict = h.copy()
        if 'Date' not in header_dict:
            now = datetime.now()
            stamp = mktime(now.timetuple())
            header_dict['Date'] = format_date_time(stamp)
        if self.headers:
            signable_list = [header_dict[x] for x in self.headers]
            signable = '\n'.join(signable_list)
        else:
            signable = header_dict['Date']
        signature = self.signer.sign(signable)
        header_dict['Authorization'] = self.signature_string_head % signature
        return header_dict

