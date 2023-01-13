//*************************************************************************************/
///* Copyright (C) 2022 - Renaud Dubois - This file is part of Cairo_musig2 project	 */
///* License: This software is licensed under a dual BSD and GPL v2 license. 	 */
///* See LICENSE file at the root folder of the project.				 */
///* FILE: test_multipoint.cairo						         */
///* 											 */
///* 											 */
///* DESCRIPTION:  testing file for ec_mulmuladd over sec256k1 curve			 */
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



func test_ecmulmuladd{range_check_ptr }()->(res:felt){
   %{ print("\n******************* Unitary Test 1: test mulmuladd (Shamir) on single precision scalar") %}
     let G=EcPoint(BigInt3(GX0, GX1, GX2), BigInt3(GY0, GY1, GY2));
     
    
     let Q:EcPoint=ec_double(G);

     let scal_3=3;
     let scal_31=31;
     let m1=-1;	
    
     //compute 3G+31Q= 65G
     let computed:EcPoint=ec_mulmuladd( G, Q, scal_3, scal_31);
     let compX=computed.x.d0;
     %{ print("\n Computed x=", ids.compX) %}
     
     let soixantecinq=BigInt3(0x41, 0x0, 0x0);
     
     let expected:EcPoint=ec_mul(G, soixantecinq);
     let expX=expected.x.d0;
     
    
     %{  print("\n Expected x=", ids.expX) %}
 return (res=1);
}


func test_ecmulmuladdW{range_check_ptr }()->(res:felt){
 	alloc_locals;
   %{ print("\n******************* Unitary Test 2: test mulmuladd (windowed Shamir version) on single precision scalar") %}
     let G=EcPoint(BigInt3(GX0, GX1, GX2), BigInt3(GY0, GY1, GY2));
    
     
    
     let Q:EcPoint=ec_double(G);

     let scal_3=3;
     let scal_31=31;
     let m1=-1;	
    
     //compute 3G+31Q= 65G
     let computed:EcPoint=ec_mulmuladd_W( G, Q, scal_3, scal_31);
     let compX=computed.x.d0;
     %{ print("\n Computed x=", ids.compX) %}
     io_printPoint(computed);
     
     let soixantecinq=BigInt3(0x41, 0x0, 0x0);
     
     let expected:EcPoint=ec_mul(G, soixantecinq);
     let expX=expected.x.d0;
     
    
     %{  print("\n Expected x=", ids.expX) %}
     io_printPoint(expected);

     let cmp:felt=ec_test_eq(expected, computed);
     %{  print("\n Is Expected =Computed :", ids.cmp) %}
     
     
 return (res=cmp);
}

//print in hexadecimal, aligned on 128 bits (easier debug)
func io_printBigInt3{range_check_ptr }(bg3_a: BigInt3){
    
    //let low=bg3_a.d0+((bg3_a.d1&0xffffffff)<<86);
    //let hi=(bg3_a.d1>>(86-32))+(bg3_a.d2<<(86-32))
    %{ print("\n ", hex(ids.bg3_a.d0+((ids.bg3_a.d1&0x3ffffffffff)<<86)),hex((ids.bg3_a.d1>>(42))+(ids.bg3_a.d2<<(44))))  %}
 
    return();
}

func io_printPoint{range_check_ptr }(ec_G: EcPoint){
    %{ print("\n x:") %}
    io_printBigInt3(ec_G.x);
    %{ print("\n y:") %}
   
    io_printBigInt3(ec_G.y);
    
     return();
}

func bg3_test_eq{range_check_ptr }( bg3_a:BigInt3, bg3_b:BigInt3)->(res:felt){
    
    if(bg3_a.d0!=bg3_b.d0){
        let res=0;
        return (res=res);
    }
    if(bg3_a.d1!=bg3_b.d1){
        let res=1;
        return (res=res);
    }
    if(bg3_a.d2!=bg3_b.d2){
        let res=1;
        return (res=res);
    }
    
    
    
    let res=1;
    return (res=res);
}

func ec_test_eq{range_check_ptr }(ec_G: EcPoint, ec_Q: EcPoint)->(res:felt){

    let testx:felt=bg3_test_eq(ec_G.x,ec_Q.x);
    if(testx==0){
    	return (res=testx);
    }
    
    let testy:felt=bg3_test_eq(ec_G.y,ec_Q.y);
    if(testy==0){
    	return (res=testy);
    }
    let res=1;
    
    
    return (res=res);
}

func test_naive{range_check_ptr }(){
 %{ print("\n******************* Unitary Test 0: test mulmuladd naive and IO functions") %}
    alloc_locals;
//* parameters for 256k1:
//https://en.bitcoin.it/wiki/Secp256k1
//order=115792089237316195423570985008687907852837564279074904382605163141518161494337
//low=hex(n&(2^86-1)), med=hex((n>>86)&(2^86-1)), hi=hex((n>>(2*86))&(2^84-1))
//0x8a03bbfd25e8cd0364141 , 0x3ffffffffffaeabb739abd, 0xfffffffffffffffffffff
//int(low,16)+(int(med,16)<<86)+(int(hi,16)<<2*86)  
    
    
  let G=EcPoint(BigInt3(GX0, GX1, GX2), BigInt3(GY0, GY1, GY2));
    
   io_printPoint(G);
   
 let Q:EcPoint=ec_double(G);



//u=N-1, vP=-P
let scalar_u=BigInt3(0x179e84f3b9cac2fc632550 , 0x3ffffffffffef39beab69c, 0xffffffff00000000fffff);
 
//v=N+1, (N+1)Q=2G    
let scalar_v=BigInt3(0x179e84f3b9cac2fc632552 , 0x3ffffffffffef39beab69c, 0xffffffff00000000fffff);

 //(qG)+(q-2)*G shall be equal to P using Fermat theorem
 let res:EcPoint=ec_mulmuladd_naive(G,Q,scalar_u, scalar_v); 


   io_printPoint(res);
 
 let cmp:felt=ec_test_eq(res, G);

 
  %{  print("\n cmp =", ids.cmp) %}
 return();
}


func test_full_windowed{range_check_ptr }(){
 %{ print("\n******************* Unitary Test 3: test windowed sharmir's trick mulmuladd :") %}
 
 
 let G=EcPoint(BigInt3(GX0, GX1, GX2), BigInt3(GY0, GY1, GY2));
  
   io_printPoint(G);
   
 let Q:EcPoint=ec_double(G);
 
 
//u=N-1, vP=-P
let scalar_u=BigInt3(0x179e84f3b9cac2fc632550 , 0x3ffffffffffef39beab69c, 0xffffffff00000000fffff);
  
//v=N+1, (N+1)Q=2G    
let scalar_v=BigInt3(0x179e84f3b9cac2fc632552 , 0x3ffffffffffef39beab69c, 0xffffffff00000000fffff);

 //(N-1)G+(N+1)*G shall be equal to P using Fermat theorem
 let res:EcPoint=ec_mulmuladdW_bg3(G,Q,scalar_u, scalar_v); 


   io_printPoint(res);
 
 let cmp:felt=ec_test_eq(res, G);

 
  %{  print("\n cmp =", ids.cmp) %}
 return();
 }
 
 
//////////// MAIN
func main{range_check_ptr }() {
    alloc_locals;
    let (__fp__, _) = get_fp_and_pc();
    
    
     %{ print("\n*******************CAIRO:Shamir's trick+Windowing testing over sec256r1") %}//result of signature
    
    
    test_naive();
    test_ecmulmuladd();
    test_ecmulmuladdW();
    test_full_windowed();
    
    return(); 
}     
     

