# From: https://github.com/EulerSmile/common-ec-cairo

from starkware.cairo.common.cairo_secp.bigint import BigInt3, UnreducedBigInt3, UnreducedBigInt5, nondet_bigint3, bigint_mul
from starkware.cairo.common.cairo_secp.constants import BASE
from starkware.cairo.common.cairo_secp.ec import EcPoint

from src.bigint import bigint_div_mod, verify_urbigint5_zero
from src.param_def import P0, P1, P2, N0, N1, N2, A0, A1, A2, GX0, GX1, GX2, GY0, GY1, GY2
from src.field import verify_zero, is_zero, unreduced_mul, unreduced_sqr

# Computes the slope of the elliptic curve at a given point.
# The slope is used to compute point + point.
#
# Arguments:
#   point - the point to operate on.
#
# Returns:
#   slope - the slope of the curve at point, in BigInt3 representation.
#
# Assumption: point != 0.
func compute_doubling_slope{range_check_ptr}(point : EcPoint, p : BigInt3, a : BigInt3, secp_rem : felt) -> (slope : BigInt3):
    # Note that y cannot be zero: assume that it is, then point = -point, so 2 * point = 0, which
    # contradicts the fact that the size of the curve is odd.
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        from starkware.python.math_utils import ec_double_slope

        # Compute the slope.
        x = pack(ids.point.x, PRIME)
        y = pack(ids.point.y, PRIME)
        p = pack(ids.p, PRIME)
        a = pack(ids.a, PRIME)
        # print(x, y, p, a)
        value = slope = ec_double_slope(point=(x, y), alpha=a, p=p)
    %}
    let (slope : BigInt3) = nondet_bigint3()

    let (x_sqr : UnreducedBigInt3) = unreduced_sqr(point.x, secp_rem)
    let (slope_y : UnreducedBigInt3) = unreduced_mul(slope, point.y, secp_rem)

    # verify_zero(
    #     UnreducedBigInt3(
    #     d0=3 * x_sqr.d0 + a.d0 - 2 * slope_y.d0,
    #     d1=3 * x_sqr.d1 + a.d1 - 2 * slope_y.d1,
    #     d2=3 * x_sqr.d2 + a.d2 - 2 * slope_y.d2), p, secp_rem
    # )

    return (slope=slope)
end

# Computes the slope of the line connecting the two given points.
# The slope is used to compute point0 + point1.
#
# Arguments:
#   point0, point1 - the points to operate on.
#
# Returns:
#   slope - the slope of the line connecting point0 and point1, in BigInt3 representation.
#
# Assumptions:
# * point0.x != point1.x (mod P).
# * point0, point1 != 0.
func compute_slope{range_check_ptr}(point0 : EcPoint, point1 : EcPoint, p : BigInt3, secp_rem : felt) -> (slope : BigInt3):
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        from starkware.python.math_utils import line_slope

        # Compute the slope.
        x0 = pack(ids.point0.x, PRIME)
        y0 = pack(ids.point0.y, PRIME)
        x1 = pack(ids.point1.x, PRIME)
        y1 = pack(ids.point1.y, PRIME)
        p = pack(ids.p, PRIME)
        # print("p0x", ids.point0.x.d0, ids.point0.x.d1, ids.point0.x.d2)
        # print("p0y", ids.point0.y.d0, ids.point0.y.d1, ids.point0.y.d2)
        # print("p1x", ids.point1.x.d0, ids.point1.x.d1, ids.point1.x.d2)
        # print("p1y", ids.point1.y.d0, ids.point1.y.d1, ids.point1.y.d2)
        value = slope = line_slope(point1=(x0, y0), point2=(x1, y1), p=p)
    %}
    let (slope) = nondet_bigint3()

    let x_diff = BigInt3(
        d0=point0.x.d0 - point1.x.d0, d1=point0.x.d1 - point1.x.d1, d2=point0.x.d2 - point1.x.d2
    )
    let (x_diff_slope : UnreducedBigInt3) = unreduced_mul(x_diff, slope, secp_rem)

    # verify_zero(
    #     UnreducedBigInt3(
    #     d0=x_diff_slope.d0 - point0.y.d0 + point1.y.d0,
    #     d1=x_diff_slope.d1 - point0.y.d1 + point1.y.d1,
    #     d2=x_diff_slope.d2 - point0.y.d2 + point1.y.d2), p, secp_rem
    # )

    return (slope)
end

# Computes the addition of a given point to itself.
#
# Arguments:
#   point - the point to operate on.
#
# Returns:
#   res - a point representing point + point.
func ec_double{range_check_ptr}(point : EcPoint, p : BigInt3, secp_rem : felt) -> (res : EcPoint):
    # The zero point.
    if point.x.d0 == 0:
        if point.x.d1 == 0:
            if point.x.d2 == 0:
                return (point)
            end
        end
    end

    let a = BigInt3(A0, A1, A2)
    let (slope : BigInt3) = compute_doubling_slope(point, p, a, secp_rem)
    let (slope_sqr : UnreducedBigInt3) = unreduced_sqr(slope, secp_rem)

    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        slope = pack(ids.slope, PRIME)
        x = pack(ids.point.x, PRIME)
        y = pack(ids.point.y, PRIME)
        p = pack(ids.p, PRIME)

        value = new_x = (pow(slope, 2, p) - 2 * x) % p
    %}
    let (new_x : BigInt3) = nondet_bigint3()

    %{ value = new_y = (slope * (x - new_x) - y) % p %}
    let (new_y : BigInt3) = nondet_bigint3()

    # verify_zero(
    #     UnreducedBigInt3(
    #     d0=slope_sqr.d0 - new_x.d0 - 2 * point.x.d0,
    #     d1=slope_sqr.d1 - new_x.d1 - 2 * point.x.d1,
    #     d2=slope_sqr.d2 - new_x.d2 - 2 * point.x.d2), p, secp_rem
    # )

    # let (x_diff_slope : UnreducedBigInt3) = unreduced_mul(
    #     BigInt3(d0=point.x.d0 - new_x.d0, d1=point.x.d1 - new_x.d1, d2=point.x.d2 - new_x.d2), slope, secp_rem
    # )

    # verify_zero(
    #     UnreducedBigInt3(
    #     d0=x_diff_slope.d0 - point.y.d0 - new_y.d0,
    #     d1=x_diff_slope.d1 - point.y.d1 - new_y.d1,
    #     d2=x_diff_slope.d2 - point.y.d2 - new_y.d2), p, secp_rem
    # )

    return (res=EcPoint(new_x, new_y))
end

# Computes the addition of two given points.
#
# Arguments:
#   point0, point1 - the points to operate on.
#
# Returns:
#   res - the sum of the two points (point0 + point1).
#
# Assumption: point0.x != point1.x (however, point0 = point1 = 0 is allowed).
# Note that this means that the function cannot be used if point0 = point1 != 0
# (use ec_double() in this case) or point0 = -point1 != 0 (the result is 0 in this case).
func fast_ec_add{range_check_ptr}(point0 : EcPoint, point1 : EcPoint, p : BigInt3, secp_rem : felt) -> (res : EcPoint):
    # Check whether point0 is the zero point.
    if point0.x.d0 == 0:
        if point0.x.d1 == 0:
            if point0.x.d2 == 0:
                return (point1)
            end
        end
    end

    # Check whether point1 is the zero point.
    if point1.x.d0 == 0:
        if point1.x.d1 == 0:
            if point1.x.d2 == 0:
                return (point0)
            end
        end
    end

    let (slope : BigInt3) = compute_slope(point0, point1, p, secp_rem)
    let (slope_sqr : UnreducedBigInt3) = unreduced_sqr(slope, secp_rem)

    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack

        slope = pack(ids.slope, PRIME)
        x0 = pack(ids.point0.x, PRIME)
        x1 = pack(ids.point1.x, PRIME)
        y0 = pack(ids.point0.y, PRIME)
        p = pack(ids.p, PRIME)

        value = new_x = (pow(slope, 2, p) - x0 - x1) % p
    %}
    let (new_x : BigInt3) = nondet_bigint3()

    %{ value = new_y = (slope * (x0 - new_x) - y0) % p %}
    let (new_y : BigInt3) = nondet_bigint3()

    # verify_zero(
    #     UnreducedBigInt3(
    #     d0=slope_sqr.d0 - new_x.d0 - point0.x.d0 - point1.x.d0,
    #     d1=slope_sqr.d1 - new_x.d1 - point0.x.d1 - point1.x.d1,
    #     d2=slope_sqr.d2 - new_x.d2 - point0.x.d2 - point1.x.d2), p, secp_rem
    # )

    let (x_diff_slope : UnreducedBigInt3) = unreduced_mul(
        BigInt3(d0=point0.x.d0 - new_x.d0, d1=point0.x.d1 - new_x.d1, d2=point0.x.d2 - new_x.d2),
        slope, secp_rem
    )

    # verify_zero(
    #     UnreducedBigInt3(
    #     d0=x_diff_slope.d0 - point0.y.d0 - new_y.d0,
    #     d1=x_diff_slope.d1 - point0.y.d1 - new_y.d1,
    #     d2=x_diff_slope.d2 - point0.y.d2 - new_y.d2), p, secp_rem
    # )

    return (EcPoint(new_x, new_y))
end

# Same as fast_ec_add, except that the cases point0 = +/-point1 are supported.
func ec_add{range_check_ptr}(point0 : EcPoint, point1 : EcPoint, p : BigInt3, secp_rem : felt) -> (res : EcPoint):
    let x_diff = BigInt3(
        d0=point0.x.d0 - point1.x.d0, d1=point0.x.d1 - point1.x.d1, d2=point0.x.d2 - point1.x.d2
    )

    let (same_x : felt) = is_zero(x_diff, p, secp_rem)
    if same_x == 0:
        # point0.x != point1.x so we can use fast_ec_add.
        return fast_ec_add(point0, point1, p, secp_rem)
    end

    # We have point0.x = point1.x. This implies point0.y = +/-point1.y.
    # Check whether point0.y = -point1.y.
    let y_sum = BigInt3(
        d0=point0.y.d0 + point1.y.d0, d1=point0.y.d1 + point1.y.d1, d2=point0.y.d2 + point1.y.d2
    )
    let (opposite_y : felt) = is_zero(y_sum, p, secp_rem)
    if opposite_y != 0:
        # point0.y = -point1.y.
        # Note that the case point0 = point1 = 0 falls into this branch as well.
        let ZERO_POINT = EcPoint(BigInt3(0, 0, 0), BigInt3(0, 0, 0))
        return (ZERO_POINT)
    else:
        # point0.y = point1.y.
        return ec_double(point0, p, secp_rem)
    end
end


# Given a scalar, an integer m in the range [0, 250), and a point on the elliptic curve, point,
# verifies that 0 <= scalar < 2**m and returns (2**m * point, scalar * point).
func ec_mul_inner{range_check_ptr}(point : EcPoint, scalar : felt, m : felt, p : BigInt3, secp_rem : felt) -> (
    pow2 : EcPoint, res : EcPoint
):
    if m == 0:
        with_attr error_message("Too large scalar"):
            scalar = 0
        end
        let ZERO_POINT = EcPoint(BigInt3(0, 0, 0), BigInt3(0, 0, 0))
        return (pow2=point, res=ZERO_POINT)
    end

    alloc_locals
    let (double_point : EcPoint) = ec_double(point, p, secp_rem)
    %{ memory[ap] = (ids.scalar % PRIME) % 2 %}
    jmp odd if [ap] != 0; ap++
    return ec_mul_inner(double_point, scalar / 2, m - 1, p, secp_rem)

    odd:
    let (local inner_pow2 : EcPoint, inner_res : EcPoint) = ec_mul_inner(
        double_point, (scalar - 1) / 2, m - 1, p, secp_rem
    )
    # Here inner_res = (scalar - 1) / 2 * double_point = (scalar - 1) * point.
    # Assume point != 0 and that inner_res = +/-point. We obtain (scalar - 1) * point = +/-point =>
    # scalar - 1 = +/-1 (mod N) => scalar = 0 or 2 (mod N).
    # By induction, we know that (scalar - 1) / 2 must be in the range [0, 2**(m-1)),
    # so scalar is an odd number in the range [0, 2**m), and we get a contradiction.
    let (res : EcPoint) = fast_ec_add(point, inner_res, p, secp_rem)
    return (pow2=inner_pow2, res=res)
end

# Given a point and a 256-bit scalar, returns scalar * point.
func ec_mul{range_check_ptr}(point : EcPoint, scalar : BigInt3, p : BigInt3, secp_rem : felt) -> (res : EcPoint):
    alloc_locals
    let (pow2_0 : EcPoint, local res0 : EcPoint) = ec_mul_inner(point, scalar.d0, 86, p, secp_rem)
    let (pow2_1 : EcPoint, local res1 : EcPoint) = ec_mul_inner(pow2_0, scalar.d1, 86, p, secp_rem)
    let (_, local res2 : EcPoint) = ec_mul_inner(pow2_1, scalar.d2, 84, p, secp_rem)
    let (res : EcPoint) = ec_add(res0, res1, p, secp_rem)
    let (res : EcPoint) = ec_add(res, res2, p, secp_rem)
    return (res)
end

# Verify a point lies on the curve.
# In the EC lib, we don't use `b` parameter explictly,
# so to verify whether a point lies on the curve or not,
# we use `G` to compare.
# y_G^2 - y_pt^2 = x_G^3 - x_pt^3 + a(x_G - x_pt) =>
# (y_G - y_pt)(y_G + y_pt) = (x_G^2 + x_G*x_pt + x_pt^2 + a)(x_G - x_pt)
func verify_point{range_check_ptr}(pt: EcPoint):
    let GX = BigInt3(GX0, GX1, GX2)
    let P = BigInt3(P0, P1, P2)

    let (gx2) = bigint_mul(GX, GX)
    let (gkx_prod) = bigint_mul(pt.x, GX)
    let (kx2) = bigint_mul(pt.x, pt.x)

    let (q) = bigint_div_mod(
        UnreducedBigInt5(
            d0 = gx2.d0 + gkx_prod.d0 + kx2.d0 + A0,
            d1 = gx2.d1 + gkx_prod.d1 + kx2.d1 + A1,
            d2 = gx2.d2 + gkx_prod.d2 + kx2.d2 + A2,
            d3 = gx2.d3 + gkx_prod.d3 + kx2.d3,
            d4 = gx2.d4 + gkx_prod.d4 + kx2.d4
        ), UnreducedBigInt3(1, 0, 0), P)

    # check left == right
    let gky_diff = BigInt3(
        d0 = GY0 - pt.y.d0,
        d1 = GY1 - pt.y.d1,
        d2 = GY2 - pt.y.d2
    )
    let gky_sum = BigInt3(
        d0 = GY0 + pt.y.d0,
        d1 = GY1 + pt.y.d1,
        d2 = GY2 + pt.y.d2
    )
    let gkx_diff = BigInt3(
        d0 = GX0 - pt.x.d0,
        d1 = GX1 - pt.x.d1,
        d2 = GX2 - pt.x.d2
    )
    let (left_diff) = bigint_mul(gky_diff, gky_sum)
    let (right_diff) = bigint_mul(q, gkx_diff)

    verify_urbigint5_zero(
        UnreducedBigInt5(
        d0 = left_diff.d0 - right_diff.d0,
        d1 = left_diff.d1 - right_diff.d1,
        d2 = left_diff.d2 - right_diff.d2,
        d3 = left_diff.d3 - right_diff.d3,
        d4 = left_diff.d4 - right_diff.d4,
    ), P)

    return ()
end