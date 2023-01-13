//*************************************************************************************/
///* Copyright (C) 2022 - Renaud Dubois - This file is part of Cairo_musig2 project	 */
///* License: This software is licensed under a dual BSD and GPL v2 license. 	 */
///* See LICENSE file at the root folder of the project.				 */
///* FILE: test_ecdsa_opti.cairo						         */
///* 											 */
///* 											 */
///* DESCRIPTION:  testing file for ecdsa speed up with mulmuladd over sec256r1 curve */
//**************************************************************************************/

//Shamir's trick:https://crypto.stackexchange.com/questions/99975/strauss-shamir-trick-on-ec-multiplication-by-scalar,
//Windowing method : https://en.wikipedia.org/wiki/Exponentiation_by_squaring, section 'sliding window'
//The implementation use a 2 bits window with trick, leading to a 16 points elliptic point precomputation

%builtins range_check 

from starkware.cairo.common.cairo_builtins import EcOpBuiltin 
from starkware.cairo.common.registers import get_ap
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math_cmp import is_nn_le
from starkware.cairo.common.cairo_secp.bigint import BigInt3, UnreducedBigInt3, nondet_bigint3
from starkware.cairo.common.cairo_secp.field import (
    is_zero,
    unreduced_mul,
    unreduced_sqr,
    verify_zero,
)

from src.ec import EcPoint, ec_add, ec_mul, ec_double

from src.param_def import N0, N1, N2, GX0, GX1, GX2, GY0, GY1, GY2
from src.ec_mulmuladd import ec_mulmuladd_W, ec_mulmuladd, ec_mulmuladd_naive
from src.ec_mulmuladd_secp256r1 import  ec_mulmuladdW_bg3

from src.ecdsa import verify_ecdsa


func test_verify_ecdsa{range_check_ptr}() {
    let public_key_pt = EcPoint(
        BigInt3(0x3fb12f3c59ff46c271bf83, 0x3e89236e3f334d5977a52e, 0x1ccbe91c075fc7f4f033b),
        BigInt3(0x4e78dc7ccd5ca89a4ca9, 0x2cb039844f81b6df2a4edd, 0xce4014c68811f9a21a1fd),
    );
    let r = BigInt3(0x155a7acabb5e6f79c8c2ac, 0xf598a549fb4abf5ac7da9, 0xf3ac8061b514795b8843e);
    let s = BigInt3(0x2f175a3ccdda2acc058903, 0x1898afdcdc73be5ec863a5, 0x8bf77819ca05a6b2786c7);
    let msg_hash = BigInt3(
        0x100377dbc4e7a6a133ec56, 0x25c813f825413878bbec6a, 0x44acf6b7e36c1342c2c58
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}


//////////// MAIN
func main{ range_check_ptr}() {
    alloc_locals;
    let (__fp__, _) = get_fp_and_pc();
    
    
     %{ print("\n ECDSA standard implementation over sec256r1") %}//result of signature
    
    
    test_verify_ecdsa();
   
    
    return(); 
}     
