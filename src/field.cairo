# From: https://github.com/EulerSmile/common-ec-cairo

from starkware.cairo.common.math import assert_nn_le, assert_not_zero
from starkware.cairo.common.cairo_secp.bigint import BigInt3, UnreducedBigInt3, UnreducedBigInt5
from starkware.cairo.common.cairo_secp.constants import BASE

from src.bigint import bigint_div_mod

#return 1 if x ==0 mod n
func is_urbigInt3_zero{range_check_ptr}(x : BigInt3, n : BigInt3) -> (res : felt):
    let (xn) = bigint_div_mod(UnreducedBigInt5(d0=x.d0, d1=x.d1, d2=x.d2, 0, 0), UnreducedBigInt3(1, 0, 0), n)
    if xn.d0 == 0:
        if xn.d1 == 0:
            if xn.d2 == 0:
                return (res = 1)
            end
        end
    end
    return (res = 0)
end

# Verifies that the given unreduced value is equal to zero modulo the secp256k1 prime.
#
# Completeness assumption: val's limbs are in the range (-2**210.99, 2**210.99).
# Soundness assumption: val's limbs are in the range (-2**250, 2**250).
func verify_zero{range_check_ptr}(val : UnreducedBigInt3, P: BigInt3):
    let q = [ap]
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        P = pack(ids.P, PRIME)
        q, r = divmod(pack(ids.val, PRIME), P)
        assert r == 0, f"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}."
        ids.q = q % PRIME
    %}
    let q_biased = [ap + 1]
    q_biased = q + 2 ** 127; ap++
    [range_check_ptr] = q_biased; ap++
    # This implies that q is in the range [-2**127, 2**127).

    tempvar r1 = (val.d0 + q * SECP_REM) / BASE
    assert [range_check_ptr + 1] = r1 + 2 ** 127
    # This implies that r1 is in the range [-2**127, 2**127).
    # Therefore, r1 * BASE is in the range [-2**213, 2**213).
    # By the soundness assumption, val.d0 is in the range (-2**250, 2**250).
    # This implies that r1 * BASE = val.d0 + q * SECP_REM (as integers).

    tempvar r2 = (val.d1 + r1) / BASE
    assert [range_check_ptr + 2] = r2 + 2 ** 127
    # Similarly, this implies that r2 * BASE = val.d1 + r1 (as integers).
    # Therefore, r2 * BASE**2 = val.d1 * BASE + r1 * BASE.

    assert val.d2 = q * (BASE / 4) - r2
    # Similarly, this implies that q * BASE / 4 = val.d2 + r2 (as integers).
    # Therefore,
    #   q * BASE**3 / 4 = val.d2 * BASE**2 + r2 * BASE ** 2 =
    #   val.d2 * BASE**2 + val.d1 * BASE + r1 * BASE =
    #   val.d2 * BASE**2 + val.d1 * BASE + val.d0 + q * SECP_REM =
    #   val + q * SECP_REM.
    # Hence, val = q * (BASE**3 / 4 - SECP_REM) = q * (2**256 - SECP_REM) = q * secp256k1_prime.

    let range_check_ptr = range_check_ptr + 3
    return ()
end
