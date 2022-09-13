// Basic definitions for the secp256r1 elliptic curve.
// The curve is given by the equation:
//   y^2 = x^3 + ax + b
// where:
//   a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
//   b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
// over the field Z/p for
//   p = 2**224(2**32-1) + 2**192 + 2**96 - 1
//   p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
// The size of the curve is
//   n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 (prime).

// The domain paramters of elliptic curve.

const P0 = 0x3fffffffffffffffffffff;
const P1 = 0x3ff;
const P2 = 0xffffffff0000000100000;

const N0 = 0x179e84f3b9cac2fc632551;
const N1 = 0x3ffffffffffef39beab69c;
const N2 = 0xffffffff00000000fffff;

const A0 = -3;
const A1 = 0;
const A2 = 0;

const GX0 = 0x2b33a0f4a13945d898c296;
const GX1 = 0x1b958e9103c9dc0df604b7;
const GX2 = 0x6b17d1f2e12c4247f8bce;

const GY0 = 0x315ececbb6406837bf51f5;
const GY1 = 0x2d29f03e7858af38cd5dac;
const GY2 = 0x4fe342e2fe1a7f9b8ee7e;
