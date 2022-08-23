%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.cairo_secp.ec import EcPoint

from src.ec import compute_doubling_slope, compute_slope
from src.param_def import P0, P1, P2, A0, A1, A2

@view
func test_compute_doubling_slope{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    let p = BigInt3(P0, P1, P2)
    let a = BigInt3(A0, A1, A2)
    let point = EcPoint(
        BigInt3(52227620040540588600771222, 33347259622618539004134583, 8091721874918813684698062),
        BigInt3(59685082318776612195095029, 54599710628478995760242092, 6036146923926000695307902))
    compute_doubling_slope(point, p, a)
    return ()
end

@view
func test_compute_slope{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    let p = BigInt3(P0, P1, P2)
    let x = EcPoint(
        BigInt3(52227620040540588600771222, 33347259622618539004134583, 8091721874918813684698062),
        BigInt3(59685082318776612195095029, 54599710628478995760242092, 6036146923926000695307902))
    let y = EcPoint(
        BigInt3(52227620040540588600771222, 33347259622618539004134583, 8091721874918813684698062),
        BigInt3(59685082318776612195095029, 54599710628478995760242092, 6036146923926000695307902))
    compute_slope(x, y, p)
    return ()
end

# p0x 18742262007655976083952094 2170278475068009573293424 1076302195906477591003722
# p0y 34244297358526317143979340 57839944361682288439803986 1507246073876674611658538
# p1x 65152262866761155910162282 40340684474627089544018536 626417993928619776535656
# p1y 53436004282169687511911968 8831389139754503123655424 6070908525652947743172841
# p0x 50893025175252933453759862 49485110834161103961762965 420249174822888294992435
# p0y 64636676010272179975425694 54515494586623118101334401 10950646314693100832570873
# p1x 56478021091942096195514428 36994269114100132080717176 1796498911149557297579686
# p1y 31864364294177881903015887 71238495969619171078174251 11864615819113610436995202

# def ec_double_slope(point: Tuple[int, int], alpha: int, p: int) -> int:
#     """
#     Computes the slope of an elliptic curve with the equation y^2 = x^3 + alpha*x + beta mod p, at
#     the given point.
#     Assumes the point is given in affine form (x, y) and has y != 0.
#     """
#     assert point[1] % p != 0
#     return div_mod(3 * point[0] * point[0] + alpha, 2 * point[1], p)

# y^2 = x^3 + alpha*x + beta
# 0 = 2*y = 3 + x^2 + alpha
# 0 = 3 + x^2 + alpha - 2 * y

# s = 3 + x^2 + alpha / 2 * y
# sy = 3 + x^2 + alpha / 2