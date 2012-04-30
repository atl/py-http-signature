import struct

def lkv(d):
    parts = []
    while d:
            len = struct.unpack('>I', d[:4])[0]
            bits = d[4:len+4]
            parts.append(bits)
            d = d[len+4:]
    return parts

def sig(d):
    return lkv(d)[1]

def is_rsa(keyobj):
    return lkv(keyobj.blob)[0] == "ssh-rsa"
