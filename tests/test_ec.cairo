%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.math import assert_nn

from src.ec import compute_doubling_slope, compute_slope, unreduced_mul
from src.secp256r1 import P0, P1, P2, A0, A1, A2, SECP_REM as SECP_R1_REM
from src.secp256k1 import SECP_REM as SECP_K1_REM

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
    let (res0) = unreduced_mul(a0, b0, SECP_R1_REM)

    %{
        print("secp256r1", ids.res0.d0, ids.res0.d1, ids.res0.d2)
    %}

    assert_nn(res0.d0)
    assert_nn(res0.d1)
    assert_nn(res0.d2)

    return ()
end

@view
func test_unreduced_mul_secp256k1{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():    
    # secp256k1
    let a1 = BigInt3(3618502788666131213697322783095070105623107215331595159768072029637820348501, 7466994968097957739996517, 8031891367682540106321860)
    let b1 = BigInt3(57865348453739613262196532, 57067720862797319834890931, 16139035050145316868696712)
    let (res1) = unreduced_mul(a1, b1, SECP_K1_REM)

    %{
        print("secp256k1", ids.res1.d0, ids.res1.d1, ids.res1.d2)
    %}

    assert_nn(res1.d0)
    assert_nn(res1.d1)
    assert_nn(res1.d2)

    return ()
end
