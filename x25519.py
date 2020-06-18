#!/usr/bin/env python
import binascii

"""
X25519 implementation (RFC7748)
"""

p = 2**255 - 19
a24 = 121665

def decodeLittleEndian( b ):
    return sum( [ b[ i ] << 8 * i for i in range( 32 ) ] )

def decodeUCoordinate( u ):
    """
    @u: a string that represents x coordinate in little-endian order
    @return: x coordinate as an integer
    """
    u_list = [ ord( b ) for b in u ]
    # Mask the most significant bit in the final byte
    u_list[ -1 ] &= 0x7F
    return decodeLittleEndian( u_list )

def encodeUCoordinate( u ):
    """
    @u: an integer that represents x coordinate used in internal function
    @return: x coordinate as a string in litter-endian order
    """
    u = u % p
    u_list = [ chr( ( u >> 8 * i)  & 0xff ) for i in range( 32 ) ]
    return ''.join( u_list )

def decodeScalar25519( k ):
    """
    @k: a string that represents scalar
    @return: scalar as an integer
    """
    k_list = [ ord( b ) for b in k ]
    k_list[ 0 ] &= 248
    k_list[ 31 ] &= 127
    k_list[ 31 ] |= 64
    return decodeLittleEndian( k_list )

def cswap( cond, a, b ):
    """
    @cond: Conditionally swap a and b based on cond in constant time
    """
    mask = int( str( cond ) * 256, 2 )
    dummy = mask & ( a ^ b )
    a ^= dummy
    b ^= dummy
    return ( a, b )

def x25519ScalarMul( k, u ):
    k = decodeScalar25519( k )
    u = decodeUCoordinate( u )
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    t = 255
    while t != -1:
       k_t = ( k >> t ) & 1
       swap ^= k_t
       (x_2, x_3) = cswap(swap, x_2, x_3)
       (z_2, z_3) = cswap(swap, z_2, z_3)
       swap = k_t

       A = ( x_2 + z_2 ) % p
       AA = pow( A, 2, p )
       B = ( x_2 - z_2 ) % p
       BB = pow( B, 2, p )
       E = ( AA - BB ) % p
       C = ( x_3 + z_3 ) % p
       D = ( x_3 - z_3 ) % p
       DA = ( D * A ) % p
       CB = ( C * B ) % p
       x_3 = pow ( (DA + CB) % p, 2, p )
       z_3 = ( x_1 * pow( DA - CB, 2, p ) ) % p
       x_2 = ( AA * BB ) % p
       z_2 = ( E * ( ( AA + ( a24 * E ) % p ) % p ) ) % p
       t -= 1

    x_2, x_3 = cswap( swap, x_2, x_3 )
    z_2, z_3 = cswap( swap, z_2, z_3 )
    new_u = ( x_2 * pow( z_2, p - 2, p ) ) % p
    return encodeUCoordinate( new_u )

def testX25519( k, u, expectedRes ):
    k = binascii.unhexlify( k )
    u = binascii.unhexlify( u )
    expectedRes = binascii.unhexlify( expectedRes )
    assert x25519ScalarMul( k, u ) == expectedRes, "wrong multiplication result."

if __name__ == '__main__':
    # Verify with test vectors provided in RFC7748
    testX25519( 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
                'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
                'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552' )
    testX25519( '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
                'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
                '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957' )
    print "Basic test cases passed."
