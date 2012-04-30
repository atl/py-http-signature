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
    return lkv[1]
