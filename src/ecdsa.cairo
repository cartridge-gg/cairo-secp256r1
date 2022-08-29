# From: https://github.com/EulerSmile/common-ec-cairo

from starkware.cairo.common.math import assert_nn_le, assert_not_zero
from starkware.cairo.common.cairo_secp.bigint import BigInt3, UnreducedBigInt3, UnreducedBigInt5, nondet_bigint3, bigint_mul
from starkware.cairo.common.cairo_secp.constants import BASE
from starkware.cairo.common.cairo_secp.ec import EcPoint

from src.ec import ec_add, ec_mul, div_mod_n, verify_point


# Verifies that val is in the range [1, N) and that the limbs of val are in the range [0, BASE).
# Taken from: https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/cairo_secp/signature.cairo#L85
func validate_signature_entry{range_check_ptr}(val : BigInt3, n : BigInt3):
    assert_nn_le(val.d2, n.d2)
    assert_nn_le(val.d1, BASE - 1)
    assert_nn_le(val.d0, BASE - 1)

    if val.d2 == n.d2:
        if val.d1 == n.d1:
            assert_nn_le(val.d0, n.d0 - 1)
            return ()
        end
        assert_nn_le(val.d1, n.d1 - 1)
        return ()
    end

    # Check that val > 0.
    if val.d2 == 0:
        if val.d1 == 0:
            assert_not_zero(val.d0)
            return ()
        end
    end
    return ()
end

# Verifies a ECDSA signature.
# Soundness assumptions:
# * All the limbs of public_key_pt.x, public_key_pt.y, msg_hash are in the range [0, 3 * BASE).
func verify_ecdsa{range_check_ptr}(
        public_key_pt : EcPoint, g : EcPoint, n : BigInt3, a : BigInt3, p : BigInt3, secp_rem : felt, msg_hash : BigInt3, r : BigInt3, s : BigInt3):
    alloc_locals
    verify_point(public_key_pt, g, a, p)

    with_attr error_message("Signature out of range."):
        validate_signature_entry(r, n)
        validate_signature_entry(s, n)
    end

    # Compute u1 and u2.
    let (u1 : BigInt3) = div_mod_n(msg_hash, s, n)
    let (u2 : BigInt3) = div_mod_n(r, s, n)

    let (gen_u1) = ec_mul(g, u1, a, p, secp_rem)
    let (pub_u2) = ec_mul(public_key_pt, u2, a, p, secp_rem)
    let (res) = ec_add(gen_u1, pub_u2, a, p, secp_rem)

    # The following assert also implies that res is not the zero point.
    assert res.x = r

    return ()
end
