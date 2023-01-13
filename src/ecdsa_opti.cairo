// From: https://github.com/EulerSmile/common-ec-cairo

from starkware.cairo.common.math import assert_nn_le, assert_not_zero
from starkware.cairo.common.cairo_secp.bigint import BigInt3, UnreducedBigInt3, UnreducedBigInt5
from starkware.cairo.common.cairo_secp.constants import BASE
from starkware.cairo.common.cairo_secp.ec import EcPoint

from src.bigint import bigint_div_mod
from src.param_def import N0, N1, N2, GX0, GX1, GX2, GY0, GY1, GY2
from src.ec import ec_add, ec_mul, verify_point
from src.ec_mulmuladd_secp256r1 import ec_mulmuladdW_bg3

// Verifies that val is in the range [1, N) and that the limbs of val are in the range [0, BASE).
// Taken from: https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/cairo_secp/signature.cairo#L85
func validate_signature_entry{range_check_ptr}(val: BigInt3) {
    assert_nn_le(val.d2, N2);
    assert_nn_le(val.d1, BASE - 1);
    assert_nn_le(val.d0, BASE - 1);

    if (val.d2 == N2) {
        if (val.d1 == N1) {
            assert_nn_le(val.d0, N0 - 1);
            return ();
        }
        assert_nn_le(val.d1, N1 - 1);
        return ();
    }

    // Check that val > 0.
    if (val.d2 == 0) {
        if (val.d1 == 0) {
            assert_not_zero(val.d0);
            return ();
        }
    }
    return ();
}

// Verifies a ECDSA signature.
// Soundness assumptions:
// * All the limbs of public_key_pt.x, public_key_pt.y, msg_hash are in the range [0, 3 * BASE).
func verify_ecdsa_opti{range_check_ptr}(
    public_key_pt: EcPoint, msg_hash: BigInt3, r: BigInt3, s: BigInt3
) {
    alloc_locals;
    verify_point(public_key_pt);

    with_attr error_message("Signature out of range.") {
        validate_signature_entry(r);
        validate_signature_entry(s);
    }

    let gen_pt = EcPoint(BigInt3(GX0, GX1, GX2), BigInt3(GY0, GY1, GY2));

    let N = BigInt3(N0, N1, N2);
    // Compute u1 and u2.
    let (u1: BigInt3) = bigint_div_mod(
        UnreducedBigInt5(
        d0=msg_hash.d0,
        d1=msg_hash.d1,
        d2=msg_hash.d2,
        d3=0,
        d4=0
        ),
        UnreducedBigInt3(
        d0=s.d0,
        d1=s.d1,
        d2=s.d2
        ),
        N,
    );

    let (u2: BigInt3) = bigint_div_mod(
        UnreducedBigInt5(
        d0=r.d0,
        d1=r.d1,
        d2=r.d2,
        d3=0,
        d4=0
        ),
        UnreducedBigInt3(
        d0=s.d0,
        d1=s.d1,
        d2=s.d2
        ),
        N,
    );
	//using ec_mulmuladd to optimize time and cells usage
	//    let (gen_u1) = ec_mul(gen_pt, u1);
	//    let (pub_u2) = ec_mul(public_key_pt, u2);
	//    let (res) = ec_add(gen_u1, pub_u2);
	 let (res:EcPoint) =ec_mulmuladdW_bg3(gen_pt, public_key_pt, u1, u2);

	//let computed=res.x.d0;
	//let expected=r.d0;
	
     //%{ print("\n computed=",ids.computed, "expected=",ids.expected) %}//result of signature

    // The following assert also implies that res is not the zero point.
    assert res.x = r;

    return ();
}
