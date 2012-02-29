from requests.auth import AuthBase

from sign import Signer

class HTTPSignatureAuth(AuthBase):
    def __init__(self, key_id='', secret='', algorithm='rsa-sha256', headers=None):
        self.signer = Signer(secret=secret, algorithm=algorithm)
        self.algorithm = algorithm
        self.key_id = key_id
        self.headers = headers
        self.signature_string_head = self.build_header_content()
    
    def build_header_content(self):
        param_map = {'keyId': self.key_id, 
                     'algorithm': self.algorithm}
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
    
