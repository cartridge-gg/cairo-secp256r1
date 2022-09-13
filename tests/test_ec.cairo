%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_secp.bigint import BigInt3, UnreducedBigInt3, bigint_mul
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.math import assert_nn

from src.field import unreduced_mul, unreduced_mul2, unreduced_mul3
from src.ec import compute_doubling_slope, compute_slope
from src.secp256r1 import P0, P1, P2, A0, A1, A2, SECP_REM as SECP_R1_REM, P0 as P0_R1, P1 as P1_R1, P2 as P2_R1
from src.secp256k1 import SECP_REM as SECP_K1_REM, P0 as P0_K1, P1 as P1_K1, P2 as P2_K1

@view
func test_compute_doubling_slope{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    let p = BigInt3(P0, P1, P2)
    let a = BigInt3(A0, A1, A2)
    let point = EcPoint(
        BigInt3(52227620040540588600771222, 33347259622618539004134583, 8091721874918813684698062),
        BigInt3(59685082318776612195095029, 54599710628478995760242092, 6036146923926000695307902))
    compute_doubling_slope(point, p, a, SECP_R1_REM)
    return ()
end

@view
func test_compute_slope{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    let p = BigInt3(P0, P1, P2)
    
    let x = EcPoint(
        BigInt3(18742262007655976083952094, 2170278475068009573293424, 1076302195906477591003722),
        BigInt3(34244297358526317143979340, 57839944361682288439803986, 1507246073876674611658538))
    let y = EcPoint(
        BigInt3(65152262866761155910162282, 40340684474627089544018536, 626417993928619776535656),
        BigInt3(53436004282169687511911968, 8831389139754503123655424, 6070908525652947743172841))
    compute_slope(x, y, p, SECP_R1_REM)
    return ()
end

@view
func test_unreduced_mul_secp256r1{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():    
    # secp256r1
    let a0 = BigInt3(3618502788666131213697322783095070105623107215331550289972232950956045810293, 3618502788666131213697322783095070105623107215331558529567092497055901295369, 449884201977857814468066)
    let b0 = BigInt3(69068202064588144387967447, 18392539264308582722997203, 15135996811959773718392362)
    let (res0) = unreduced_mul2(a0, b0, SECP_R1_REM)

    %{
        print("secp256r1", ids.res0.d0, ids.res0.d1, ids.res0.d2)
    %}

    return ()
end

func get_r_vals() -> (a1: BigInt3, b1: BigInt3, p: BigInt3):
    let a1 = BigInt3(3618502788666131213697322783095070105623107215331550289972232950956045810293, 3618502788666131213697322783095070105623107215331558529567092497055901295369, 449884201977857814468066)
    let b1 = BigInt3(69068202064588144387967447, 18392539264308582722997203, 15135996811959773718392362)
    let p = BigInt3(d0=P0_R1, d1=P1_R1, d2=P2_R1)
    return (a1, b1, p)
end

func get_k_vals() -> (a1: BigInt3, b1: BigInt3, p: BigInt3):
    let a1 = BigInt3(3618502788666131213697322783095070105623107215331595159768072029637820348501, 7466994968097957739996517, 8031891367682540106321860)
    let b1 = BigInt3(57865348453739613262196532, 57067720862797319834890931, 16139035050145316868696712)
    let p = BigInt3(d0=P0_K1, d1=P1_K1, d2=P2_K1)
    return (a1, b1, p)
end

@view
func test_unreduced_mul_secp256k1{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    # secp256k1
    let (a1, b1, p) = get_r_vals()

    let (res1) = unreduced_mul2(a1, b1, SECP_R1_REM)
    let (res2) = unreduced_mul(a1, b1, p)
    let (res3) = unreduced_mul3(a1, b1, SECP_R1_REM)
    let (ab) = bigint_mul(a1, b1)

    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        from starkware.python.math_utils import div_mod

        BASE = 2 ** 86
        p = pack(ids.p, PRIME)
        a = pack(ids.a1, PRIME)
        b = pack(ids.b1, PRIME)

        ab = pack(ids.ab, PRIME) + as_int(ids.ab.d3, PRIME) * BASE ** 3 + as_int(ids.ab.d4, PRIME) * BASE ** 4
        assert ab == a * b


        r = div_mod(ab, 1, p)

        res1 = pack(ids.res1, PRIME)
        res3 = pack(ids.res3, PRIME) + as_int(ids.res3.d3, PRIME) + as_int(ids.res3.d4, PRIME) * BASE

        print("unreduced", ab, res1, res3)

        print(as_int(ids.res3.d0, PRIME), as_int(ids.res3.d1, PRIME), as_int(ids.res3.d2, PRIME), as_int(ids.res3.d3, PRIME), as_int(ids.res3.d4, PRIME))

        sum1 = div_mod(res1, 1, p)
        sum2 = pack(ids.res2, PRIME)
        sum3 = div_mod(res3, 1, p) 
        print("expect", r)
        print(sum1, sum2, sum3)
        assert sum1 == sum2
    %}

    return ()
end
