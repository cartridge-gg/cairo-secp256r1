%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.cairo_secp.ec import EcPoint
from src.secp256k1 import P0, P1, P2, GX0, GX1, GX2, GY0, GY1, GY2, N0, N1, N2, A0, A1, A2, SECP_REM

from src.ecdsa import verify_ecdsa

@view
func test_verify_secp256k1{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
    let gen_pt = EcPoint(
        BigInt3(GX0, GX1, GX2),
        BigInt3(GY0, GY1, GY2))
    
    let N = BigInt3(N0, N1, N2)
    let A = BigInt3(A0, A1, A2)
    let P = BigInt3(P0, P1, P2)

    let public_key_pt = EcPoint(
        BigInt3(0x35dec240d9f76e20b48b41, 0x27fcb378b533f57a6b585, 0xbff381888b165f92dd33d),
        BigInt3(0x1711d8fb6fbbf53986b57f, 0x2e56f964d38cb8dbdeb30b, 0xe4be2a8547d802dc42041))
    let r = BigInt3(0x2e6c77fee73f3ac9be1217, 0x3f0c0b121ac1dc3e5c03c6, 0xeee3e6f50c576c07d7e4a)
    let s = BigInt3(0x20a4b46d3c5e24cda81f22, 0x967bf895824330d4273d0, 0x541e10c21560da25ada4c)
    let msg_hash = BigInt3(0x38a23ca66202c8c2a72277, 0x6730e765376ff17ea8385, 0xca1ad489ab60ea581e6c1)
    verify_ecdsa(public_key_pt, gen_pt, N, A, P, SECP_REM, msg_hash, r, s)
    return ()
end
