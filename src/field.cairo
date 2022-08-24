# From: https://github.com/EulerSmile/common-ec-cairo

from starkware.cairo.common.math import assert_nn_le, assert_not_zero
from starkware.cairo.common.cairo_secp.bigint import BigInt3, UnreducedBigInt3, UnreducedBigInt5, nondet_bigint3, bigint_mul
from starkware.cairo.common.cairo_secp.constants import BASE

# Verifies that the given unreduced value is equal to zero modulo the secp256r1 prime.
#
# Completeness assumption: val's limbs are in the range (-2**210.99, 2**210.99).
# Soundness assumption: val's limbs are in the range (-2**250, 2**250).
func verify_zero{range_check_ptr}(val : UnreducedBigInt3, p : BigInt3, secp_rem : felt):
    let q = [ap]
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        p = pack(ids.p, PRIME)
        q, r = divmod(pack(ids.val, PRIME), p)
        assert r == 0, f"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}."
        ids.q = q % PRIME
    %}
    let q_biased = [ap + 1]
    q_biased = q + 2 ** 127; ap++
    [range_check_ptr] = q_biased; ap++
    # This implies that q is in the range [-2**127, 2**127).

    tempvar r1 = (val.d0 + q * secp_rem) / BASE
    assert [range_check_ptr + 1] = r1 + 2 ** 127
    # This implies that r1 is in the range [-2**127, 2**127).
    # Therefore, r1 * BASE is in the range [-2**213, 2**213).
    # By the soundness assumption, val.d0 is in the range (-2**250, 2**250).
    # This implies that r1 * BASE = val.d0 + q * secp_rem (as integers).

    tempvar r2 = (val.d1 + r1) / BASE
    assert [range_check_ptr + 2] = r2 + 2 ** 127
    # Similarly, this implies that r2 * BASE = val.d1 + r1 (as integers).
    # Therefore, r2 * BASE**2 = val.d1 * BASE + r1 * BASE.

    assert val.d2 = q * (BASE / 4) - r2
    # Similarly, this implies that q * BASE / 4 = val.d2 + r2 (as integers).
    # Therefore,
    #   q * BASE**3 / 4 = val.d2 * BASE**2 + r2 * BASE ** 2 =
    #   val.d2 * BASE**2 + val.d1 * BASE + r1 * BASE =
    #   val.d2 * BASE**2 + val.d1 * BASE + val.d0 + q * secp_rem =
    #   val + q * secp_rem.
    # Hence, val = q * (BASE**3 / 4 - secp_rem) = q * (2**256 - secp_rem) = q * secp256r1_prime.

    let range_check_ptr = range_check_ptr + 3
    return ()
end

# Computes the multiplication of two big integers, given in BigInt3 representation, modulo the
# secp256k1 prime.
#
# Arguments:
#   x, y - the two BigInt3 to operate on.
#
# Returns:
#   x * y in an UnreducedBigInt3 representation (the returned limbs may be above 3 * BASE).
#
# If each of the input limbs is in the range (-x, x), the result's limbs are guaranteed to be
# in the range (-x**2 * (2 ** 35.01), x**2 * (2 ** 35.01)) since log(8 * secp_rem + 1) < 35.01.
#
# This means that if unreduced_mul is called on the result of nondet_bigint3, or the difference
# between two such results, we have:
#   Soundness guarantee: the limbs are in the range (-2**210.18, 2**210.18).
#   Completeness guarantee: the limbs are in the range (-2**207.01, 2**207.01).
func unreduced_mul(a : BigInt3, b : BigInt3, secp_rem : felt) -> (res_low : UnreducedBigInt3):
    # The result of the product is:
    #   sum_{i, j} a.d_i * b.d_j * BASE**(i + j)
    # Since we are computing it mod secp256k1, we replace the term
    #   a.d_i * b.d_j * BASE**(i + j)
    # where i + j >= 3 with
    #   a.d_i * b.d_j * BASE**(i + j - 3) * 4 * secp_rem
    # since BASE ** 3 = 4 * secp_rem (mod secp256k1).
    return (
        UnreducedBigInt3(
        d0=a.d0 * b.d0 + (a.d1 * b.d2 + a.d2 * b.d1) * (4 * secp_rem),
        d1=a.d0 * b.d1 + a.d1 * b.d0 + (a.d2 * b.d2) * (4 * secp_rem),
        d2=a.d0 * b.d2 + a.d1 * b.d1 + a.d2 * b.d0),
    )
end

# Computes the square of a big integer, given in BigInt3 representation, modulo the
# secp256k1 prime.
#
# Has the same guarantees as in unreduced_mul(a, a).
func unreduced_sqr(a : BigInt3, secp_rem : felt) -> (res_low : UnreducedBigInt3):
    tempvar twice_d0 = a.d0 * 2
    return (
        UnreducedBigInt3(
        d0=a.d0 * a.d0 + (a.d1 * a.d2) * (2 * 4 * secp_rem),
        d1=twice_d0 * a.d1 + (a.d2 * a.d2) * (4 * secp_rem),
        d2=twice_d0 * a.d2 + a.d1 * a.d1),
    )
end

# Returns 1 if x == 0 (mod secp256r1_prime), and 0 otherwise.
#
# Completeness assumption: x's limbs are in the range (-BASE, 2*BASE).
# Soundness assumption: x's limbs are in the range (-2**107.49, 2**107.49).
func is_zero{range_check_ptr}(x : BigInt3, p : BigInt3, secp_rem : felt) -> (res : felt):
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        p = pack(ids.p, PRIME)
        x = pack(ids.x, PRIME) % p
    %}
    if nondet %{ x == 0 %} != 0:
        verify_zero(UnreducedBigInt3(d0=x.d0, d1=x.d1, d2=x.d2), p, secp_rem)
        return (res=1)
    end

    %{
        from starkware.python.math_utils import div_mod

        value = x_inv = div_mod(1, x, p)
    %}
    let (x_inv) = nondet_bigint3()
    let (x_x_inv) = unreduced_mul(x, x_inv, secp_rem)

    # Check that x * x_inv = 1 to verify that x != 0.
    verify_zero(UnreducedBigInt3(
        d0=x_x_inv.d0 - 1,
        d1=x_x_inv.d1,
        d2=x_x_inv.d2), p, secp_rem)
    return (res=0)
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
