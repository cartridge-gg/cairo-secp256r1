%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.cairo_secp.ec import EcPoint

from src.ec import compute_doubling_slope
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