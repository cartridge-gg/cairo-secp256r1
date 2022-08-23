# From: https://github.com/EulerSmile/common-ec-cairo

from starkware.cairo.common.math import assert_nn_le, assert_not_zero
from starkware.cairo.common.cairo_secp.bigint import BigInt3, UnreducedBigInt3, UnreducedBigInt5, nondet_bigint3, bigint_mul
from starkware.cairo.common.cairo_secp.constants import BASE
from starkware.cairo.common.cairo_secp.ec import EcPoint

from src.param_def import  N0, N1, N2, GX0, GX1, GX2, GY0, GY1, GY2
from src.ec import ec_add, ec_mul, verify_point


# Verifies that val is in the range [1, N) and that the limbs of val are in the range [0, BASE).
# Taken from: https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/cairo_secp/signature.cairo#L85
func validate_signature_entry{range_check_ptr}(val : BigInt3):
    assert_nn_le(val.d2, N2)
    assert_nn_le(val.d1, BASE - 1)
    assert_nn_le(val.d0, BASE - 1)

    if val.d2 == N2:
        if val.d1 == N1:
            assert_nn_le(val.d0, N0 - 1)
            return ()
        end
        assert_nn_le(val.d1, N1 - 1)
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

# Computes a * b^(-1) modulo the size of the elliptic curve (N).
#
# Prover assumptions:
# * All the limbs of x are in the range (-2 ** 210.99, 2 ** 210.99).
# * All the limbs of s are in the range (-2 ** 124.99, 2 ** 124.99).
# * s is in the range [0, 2 ** 256).
func div_mod_n{range_check_ptr}(x : BigInt3, s : BigInt3, n : BigInt3) -> (res : BigInt3):
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        from starkware.python.math_utils import div_mod, safe_div

        N = pack(ids.n, PRIME)
        x = pack(ids.x, PRIME) % N
        s = pack(ids.s, PRIME) % N
        value = res = div_mod(x, s, N)
    %}
    let (res) = nondet_bigint3()

    %{ value = k = safe_div(res * s - x, N) %}
    let (k) = nondet_bigint3()

    let (res_b) = bigint_mul(res, s)
    let (k_n) = bigint_mul(k, n)

    # We should now have res_b = k_n + x. Since the numbers are in unreduced form,
    # we should handle the carry.

    tempvar carry1 = (res_b.d0 - k_n.d0 - x.d0) / BASE
    assert [range_check_ptr + 0] = carry1 + 2 ** 127

    tempvar carry2 = (res_b.d1 - k_n.d1 - x.d1 + carry1) / BASE
    assert [range_check_ptr + 1] = carry2 + 2 ** 127

    tempvar carry3 = (res_b.d2 - k_n.d2 - x.d2 + carry2) / BASE
    assert [range_check_ptr + 2] = carry3 + 2 ** 127

    tempvar carry4 = (res_b.d3 - k_n.d3 + carry3) / BASE
    assert [range_check_ptr + 3] = carry4 + 2 ** 127

    assert res_b.d4 - k_n.d4 + carry4 = 0

    let range_check_ptr = range_check_ptr + 4

    return (res=res)
end

# Verifies a ECDSA signature.
# Soundness assumptions:
# * All the limbs of public_key_pt.x, public_key_pt.y, msg_hash are in the range [0, 3 * BASE).
func verify_ecdsa{range_check_ptr}(
        public_key_pt : EcPoint, msg_hash : BigInt3, r : BigInt3, s : BigInt3):
    alloc_locals
    verify_point(public_key_pt)

    with_attr error_message("Signature out of range."):
        validate_signature_entry(r)
        validate_signature_entry(s)
    end

    let gen_pt = EcPoint(
        BigInt3(GX0, GX1, GX2),
        BigInt3(GY0, GY1, GY2))
    
    let N = BigInt3(N0, N1, N2)
    # Compute u1 and u2.
    let (u1 : BigInt3) = div_mod_n(msg_hash, s, N)
    let (u2 : BigInt3) = div_mod_n(r, s, N)

    let (gen_u1) = ec_mul(gen_pt, u1)
    let (pub_u2) = ec_mul(public_key_pt, u2)
    let (res) = ec_add(gen_u1, pub_u2)

    # The following assert also implies that res is not the zero point.
    assert res.x = r

    return ()
end