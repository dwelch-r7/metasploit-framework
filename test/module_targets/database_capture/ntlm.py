"""Independent MS-NLMP challenge verification using target-only PyCryptodome."""
import hashlib
import hmac
import json
import struct
import sys
from Cryptodome.Cipher import DES
from Cryptodome.Hash import MD4


def security_buffer(data,position):
    length,maximum,offset=struct.unpack('<HHI',data[position:position+8])
    value=data[offset:offset+length]
    assert len(value)==length and maximum>=length
    return value


def des_key(value):
    bits=int.from_bytes(value,'big')
    return bytes(((bits >> (7*(7-index))) & 0x7f)<<1 for index in range(8))


def des_response(hashed,challenge):
    material=hashed+b'\0'*5
    return b''.join(DES.new(des_key(material[offset:offset+7]),DES.MODE_ECB).encrypt(challenge) for offset in (0,7,14))


def verify(request):
    type2=bytes.fromhex(request['type2']);type3=bytes.fromhex(request['type3'])
    assert type2[:12]==b'NTLMSSP\0\x02\0\0\0' and type3[:12]==b'NTLMSSP\0\x03\0\0\0'
    flags=int.from_bytes(type2[20:24],'little');challenge=type2[24:32]
    lm=security_buffer(type3,12);nt=security_buffer(type3,20)
    encoding='utf-16le' if int.from_bytes(type3[60:64],'little')&1 else 'ascii'
    domain=security_buffer(type3,28).decode(encoding);user=security_buffer(type3,36).decode(encoding)
    nt_hash=MD4.new(request['password'].encode('utf-16le')).digest()
    prefix=user+'::'+domain+':'
    if len(nt)>24:
        key=hmac.new(nt_hash,(user.upper()+domain).encode('utf-16le'),'md5').digest()
        assert hmac.compare_digest(nt[:16],hmac.new(key,challenge+nt[16:],'md5').digest())
        if lm!=b'\0'*24:assert hmac.compare_digest(lm[:16],hmac.new(key,challenge+lm[16:],'md5').digest())
        lines={'_netntlmv2':prefix+challenge.hex()+':'+nt[:16].hex()+':'+nt[16:].hex(),'_netlmv2':prefix+challenge.hex()+':'+lm[:16].hex()+':'+lm[16:].hex()}
        fmt='netntlmv2';private=lines['_netntlmv2']
    else:
        assert len(nt)==24
        effective=hashlib.md5(challenge+lm[:8]).digest()[:8] if flags&0x80000 and lm[8:]==b'\0'*16 else challenge
        assert hmac.compare_digest(nt,des_response(nt_hash,effective))
        lines={'_netntlm':prefix+lm.hex()+':'+nt.hex()+':'+challenge.hex()}
        fmt='netntlm';private=lines['_netntlm']
    return {'username':user,'domain':domain,'challenge':challenge.hex(),'flags':flags,'lm':lm.hex(),'nt':nt.hex(),'jtr_format':fmt,'private_data':private,'john':lines}

if __name__=='__main__':print(json.dumps(verify(json.loads(sys.argv[1]))))
