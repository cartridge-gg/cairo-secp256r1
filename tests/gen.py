import hashlib
import json
from re import sub
import binascii
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.type.univ import Sequence
from pyasn1.type.univ import Integer
from pyasn1.type.namedtype import NamedTypes
from pyasn1.type.namedtype import NamedType
import string

BASE = 2 ** 86

HEAD = """
%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.cairo_secp.ec import EcPoint

from src.ecdsa import verify_ecdsa
"""

TEST_CASE = """
@view
func test_{title}{{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}}() {
    {expect_revert}
    let public_key_pt = EcPoint(
        BigInt3({x0},{x1},{x2}),
        BigInt3({y0},{y1},{y2}));
    let r = BigInt3({r0},{r1},{r2});
    let s = BigInt3({s0},{s1},{s2});
    let msg_hash = BigInt3({m0},{m1},{m2});
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}
"""


def split(g):
    # number that need to split into 3 limbs.
    # G = G0 + G1 * BASE + G2 * BASE ^ 2
    x = divmod(g, BASE)
    y = divmod(x[0], BASE)

    g0 = x[1]
    g1 = y[1]
    g2 = y[0]

    return (g0, g1, g2)


def snake_case(s):
    return '_'.join(
        sub('([A-Z][a-z]+)', r' \1',
            sub('([A-Z]+)', r' \1',
                s.replace('-', ' '))).split()).lower()


class DERSig(Sequence):
    componentType = NamedTypes(
        NamedType('r', Integer()),
        NamedType('s', Integer())
    )


input = open('ecdsa_secp256r1_sha256_test.json')
f = open("ecdsa_secp256r1_sha256_test.cairo", "w")

data = json.load(input)

test = HEAD

for tg in data['testGroups']:
    x0, x1, x2 = split(int(tg['key']['wx'], 16))
    y0, y1, y2 = split(int(tg['key']['wy'], 16))

    for j, tc in enumerate(tg['tests']):
        try:
            title = str(
                j) + "_" + snake_case(tc['comment'].translate(str.maketrans('', '', string.punctuation)))
            msg = hashlib.sha256(binascii.unhexlify(tc["msg"])).hexdigest()
            m0, m1, m2 = split(int(msg, 16))

            sig, rest = der_decoder(
                binascii.unhexlify(tc["sig"]), asn1Spec=DERSig())
            if len(rest) != 0:
                raise Exception('Bad encoding')

            r0, r1, r2 = split(int(sig['r']))
            s0, s1, s2 = split(int(sig['s']))

            expect_revert = ""
            if tc["result"] == "invalid":
                expect_revert = "%{ expect_revert() %}"

            test += TEST_CASE.format(
                title=title,
                expect_revert=expect_revert,
                x0=x0,
                x1=x1,
                x2=x2,
                y0=y0,
                y1=y1,
                y2=y2,
                r0=r0,
                r1=r1,
                r2=r2,
                s0=s0,
                s1=s1,
                s2=s2,
                m0=m0,
                m1=m1,
                m2=m2,
            )
        except Exception as err:
            print("FAIL: {0} {1}".format(tc["msg"], err))

    break

f.write(test)
f.close()
input.close()
