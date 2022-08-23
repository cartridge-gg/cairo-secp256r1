# Basic definitions for the secp256k1 elliptic curve.
# The curve is given by the equation:
#   y^2 = x^3 + 7
# over the field Z/p for
#   p = secp256k1_prime = 2 ** 256 - (2 ** 32 + 2 ** 9 + 2 ** 8 + 2 ** 7 + 2 ** 6 + 2 ** 4 + 1).
# The size of the curve is
#   n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 (prime).

# SECP_REM is defined by the equation:
#   secp256k1_prime = 2 ** 256 - SECP_REM.
const SECP_REM = 2 ** 32 + 2 ** 9 + 2 ** 8 + 2 ** 7 + 2 ** 6 + 2 ** 4 + 1

const P0 = 0x3ffffffffffffefffffc2f
const P1 = 0x3fffffffffffffffffffff
const P2 = 0xfffffffffffffffffffff

const N0 = 0x8a03bbfd25e8cd0364141
const N1 = 0x3ffffffffffaeabb739abd
const N2 = 0xfffffffffffffffffffff

const A0 = 0
const A1 = 0
const A2 = 0

const GX0 = 0xe28d959f2815b16f81798
const GX1 = 0xa573a1c2c1c0a6ff36cb7
const GX2 = 0x79be667ef9dcbbac55a06

const GY0 = 0x554199c47d08ffb10d4b8
const GY1 = 0x2ff0384422a3f45ed1229a
const GY2 = 0x483ada7726a3c4655da4f

