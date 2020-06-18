#!/usr/bin/env python

import binascii
import x25519

print "====== Verify Test Vectors from RFC7748 ======"

alicePrivKey = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
bobPrivKey = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
print "Alice private key:", alicePrivKey
print "Bob private key:  ", bobPrivKey
alicePrivKey = binascii.unhexlify( alicePrivKey )
bobPrivKey = binascii.unhexlify( bobPrivKey )
basePoint = x25519.encodeUCoordinate( 9 )
alicePubKey = x25519.x25519ScalarMul( alicePrivKey, basePoint )
bobPubKey = x25519.x25519ScalarMul( bobPrivKey, basePoint )
print "Alice public key: ", binascii.b2a_hex( alicePubKey )
print "Bob public key:   ", binascii.b2a_hex( bobPubKey )
assert alicePubKey == binascii.unhexlify( '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a' ), \
       "wrong Alice's public key"
assert bobPubKey == binascii.unhexlify( 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f' ), \
       "wrong Bob's public key"

sharedSecretA = x25519.x25519ScalarMul( alicePrivKey, bobPubKey )
sharedSecretB = x25519.x25519ScalarMul( bobPrivKey, alicePubKey )
assert sharedSecretA == sharedSecretB, "shared secrets are not the same"
assert sharedSecretA == binascii.unhexlify( '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742' ), \
       "wrong shared secret"
print "Shared secret:    ", binascii.b2a_hex( sharedSecretA )
print "ECDH test passed."
