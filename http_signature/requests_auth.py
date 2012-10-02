from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime

from requests.auth import AuthBase

from .sign import Signer


class HTTPSignatureAuth(AuthBase):
    '''
    Sign a request using the http-signature scheme.
    https://github.com/joyent/node-http-signature/blob/master/http_signing.md
    
    key_id is the mandatory label indicating to the server which secret to use
    secret is the filename of a pem file in the case of rsa, a password string in the case of an hmac algorithm
    algorithm is one of the six specified algorithms
    headers is a list of http headers to be included in the signing string, defaulting to "Date" alone.
    '''
    def __init__(self, key_id='', secret='', algorithm='rsa-sha256', headers=None, allow_agent=False):
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
    
    def __call__(self, r):
        if 'Date' not in r.headers:
            now = datetime.now()
            stamp = mktime(now.timetuple())
            r.headers['Date'] = format_date_time(stamp)
        if self.headers:
            signable_list = [r.headers[x] for x in self.headers]
            signable = '\n'.join(signable_list)
        else:
            signable = r.headers['Date']
        signature = self.signer.sign(signable)
        r.headers['Authorization'] = self.signature_string_head % signature
        return r
    
