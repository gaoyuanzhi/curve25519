#!/usr/bin/env python

from ed25519 import *
from hashlib import sha512
import binascii

L = 2**252 + 27742317777372353535851937790883648493
g_x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
g_y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
G = (g_x, g_y, 1, g_x * g_y % p)
modp_sqrt_m1 = pow(2, (p-1) // 4, p)

def modp_inv( x ):
    return pow(x, p-2, p)

def sha512_digest( s ):
    return sha512(s).digest()

def sha512_modq(s):
    return int.from_bytes(sha512_digest(s), "little") % L

def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y*y-1) * modp_inv(d*y*y+1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    # Compute square root of x2
    x = pow(x2, (p+3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x*x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x

def point_to_int(P):
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")

def int_to_point(s):
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return (x, y, 1, x*y % p)

def s_prefix_secret( secret ):
    h = sha512_digest(secret)
    s = int.from_bytes(h[:32], "little")
    s &= (1 << 254) - 8
    s |= (1 << 254)
    return (s, h[32:])

def generate_public_key( secret ):
    s, _ = s_prefix_secret( secret )
    return point_to_int( pointMul( s, G ) )

def sign( secret, msg ):
    s, prefix = s_prefix_secret(secret)
    A = generate_public_key( secret )
    r = sha512_modq( prefix + msg )
    R = point_to_int( pointMul(r, G) )
    k = sha512_modq( R + A + msg)
    S = int.to_bytes( (r + k * s) % L, 32, "little" )
    return R + S

def verify( public, msg, signature ):
    if len(public) != 32:
        raise Exception("Bad public key length")
    if len(signature) != 64:
        Exception("Bad signature length")
    A = int_to_point(public)
    if not A:
        return False
    Ri = signature[:32]
    R = int_to_point( Ri )
    if not R:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= L:
    	return False
    k = sha512_modq(Ri + public + msg)
    sB = pointMul(S, G)
    kA = pointMul(k, A)
    return pointEqual(sB, pointAdd(R, kA))

if __name__ == "__main__":
    secret = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
    secret = binascii.unhexlify( secret )
    msg = ''
    msg = str.encode( msg )
    signature = sign( secret, msg )
    publicKey = generate_public_key( secret )
    expected_signature = binascii.unhexlify( 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b' )
    assert signature == expected_signature
    assert verify( publicKey, msg, signature )
    print ( "EdDSA basic test passed!" )
