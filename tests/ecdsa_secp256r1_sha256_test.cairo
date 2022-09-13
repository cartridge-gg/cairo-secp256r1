%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin

from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.cairo_secp.ec import EcPoint

from src.ecdsa import verify_ecdsa

@view
func test_0_signature_malleability{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}(
    ) {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        69713870038105540819344758, 9282719260041528557192170, 5805572577633930138863537
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_1_legacy_asn_encoding_of_s_misses_leading_0{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, -5805572582137529765185458
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_2_valid{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_3_long_form_encoding_of_length_of_sequence{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_4_length_of_sequence_contains_leading_0{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_67_long_form_encoding_of_length_of_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_68_long_form_encoding_of_length_of_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_69_length_of_integer_contains_leading_0{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_70_length_of_integer_contains_leading_0{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_92_appending_0s_to_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        31095831767405221664784384, 43715199886306428148235169, 216091315217881194979396525329
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_93_appending_0s_to_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        10257335913821033656418304, 17868630151907985245435856, 887176595485264250805509087561
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_94_prepending_0s_to_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_95_prepending_0s_to_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_97_appending_null_value_to_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        31095831767405221664785664, 43715199886306428148235169, 216091315217881194979396525329
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_98_appending_null_value_to_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        10257335913821033656419584, 17868630151907985245435856, 887176595485264250805509087561
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_113_dropping_value_of_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 0, 0);
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_114_dropping_value_of_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(0, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_117_modify_first_byte_of_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3146176069696016735537773
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_118_modify_first_byte_of_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 52222866759364670620710990
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_119_modify_last_byte_of_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205464, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_120_modify_last_byte_of_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451739, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_121_truncated_integer{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        41022761379972863861021742, 33128662473242552359466518, 12880046082608771024906
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_122_truncated_integer{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, -27254206792384848065939
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_123_truncated_integer{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        53636417762889409307699271, 23840024315279384476667506, 52879845826939597773880
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_124_leading_ff_in_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, -16045521316686221412922771
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_125_leading_ff_in_integer{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, -4938222916609824562566383538
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_128_replacing_integer_with_zero{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 0, 0);
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_129_replacing_integer_with_zero{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(0, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_130_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        7890459635259577116611433, 47471075518439128542792996, 22640104906478312551352941
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_131_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28153951514718313622603975, 47471075518441434003496939, -16045521312182621786600851
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_132_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        20663420652679188220989928, 29900176936895985908050296, -3297291797147845382376046
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_133_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        49217300940617953558591289, 29900176936894833177698324, 16045521312182621786600850
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_134_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        69480792820076690064583831, 29900176936897138638402267, -22640104906478312551352942
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_135_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 22640104910981912177674861
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_136_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        20663420652679188220989928, 29900176936895985908050296, 16045521316686221412922770
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 13537240531696537030113358
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_137_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        64765142993108257037053228, 68088533195292433163299149, 32880053641027004199090254
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_138_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        7657382417230726361850506, 68088533195294738624003093, -5805572577633930138863538
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_139_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        41159989750166775481743397, 9282719260042681287544142, -13537240531696537030113359
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_140_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        12606109462228010144142036, 9282719260043834017896114, -32880053641027004199090255
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_141_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        36211262705169491699451867, 68088533195293585893651121, 32880053645530603825412174
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_142_modified_r_or_s_eg_by_adding_or_subtracting_the_order_of_the_group{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56707831802657078960205336, 47471075518440281273144967, 3297291797147845382376045
    );
    let s = BigInt3(
        41159989750166775481743397, 9282719260042681287544142, 5805572582137529765185457
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_143_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 0, 0);
    let s = BigInt3(0, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_144_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 0, 0);
    let s = BigInt3(1, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_145_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 0, 0);
    let s = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_146_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 0, 0);
    let s = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_147_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 0, 0);
    let s = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_148_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 0, 0);
    let s = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_149_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 0, 0);
    let s = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_150_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 0, 0);
    let s = BigInt3(0, 1024, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_153_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(1, 0, 0);
    let s = BigInt3(0, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_154_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(1, 0, 0);
    let s = BigInt3(1, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_155_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(1, 0, 0);
    let s = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_156_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(1, 0, 0);
    let s = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_157_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(1, 0, 0);
    let s = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_158_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(1, 0, 0);
    let s = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_159_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(1, 0, 0);
    let s = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_160_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(1, 0, 0);
    let s = BigInt3(0, 1024, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_163_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let s = BigInt3(0, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_164_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let s = BigInt3(1, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_165_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let s = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_166_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let s = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_167_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let s = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_168_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let s = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_169_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let s = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_170_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let s = BigInt3(0, 1024, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_173_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(0, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_174_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(1, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_175_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_176_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_177_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_178_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_179_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_180_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(0, 1024, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_183_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(0, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_184_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(1, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_185_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_186_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_187_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_188_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_189_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_190_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(0, 1024, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_193_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(0, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_194_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(1, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_195_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_196_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_197_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_198_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_199_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_200_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let s = BigInt3(0, 1024, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_203_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let s = BigInt3(0, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_204_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let s = BigInt3(1, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_205_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let s = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_206_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let s = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_207_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let s = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_208_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let s = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_209_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let s = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_210_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let s = BigInt3(0, 1024, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_213_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 1024, 19342813109330467168976896);
    let s = BigInt3(0, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_214_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 1024, 19342813109330467168976896);
    let s = BigInt3(1, 0, 0);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_215_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 1024, 19342813109330467168976896);
    let s = BigInt3(77371252455336267181195263, 77371252455336267181195263, -1);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_216_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 1024, 19342813109330467168976896);
    let s = BigInt3(
        28553880287938765337601361, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_217_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 1024, 19342813109330467168976896);
    let s = BigInt3(
        28553880287938765337601360, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_218_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 1024, 19342813109330467168976896);
    let s = BigInt3(
        28553880287938765337601362, 77371252455335114450843292, 19342813109330467168976895
    );
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_219_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 1024, 19342813109330467168976896);
    let s = BigInt3(77371252455336267181195263, 1023, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_220_signature_with_special_case_values_for_r_and_s{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    %{ expect_revert() %}
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(0, 1024, 19342813109330467168976896);
    let s = BigInt3(0, 1024, 19342813109330467168976896);
    let msg_hash = BigInt3(
        47207284670552634608865315, 9474552886263439465319596, 14155979467491399350277174
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_229_edge_case_for_shamir_multiplication{
    syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*
}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        52746123191035088300968334, 76165563726018601894333752, 7603501997133521110758370
    );
    let s = BigInt3(
        61846177308163284558368539, 33035320460168282321446005, 8079993944091088139393568
    );
    let msg_hash = BigInt3(
        57041597306954957469448199, 20814590861019817713665470, 8472992897547922236523055
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_230_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        5179811011351127180178022, 39225303161845620767874510, 1713824034432424521168780
    );
    let s = BigInt3(
        68690606166267376028952809, 37406442089289750704423701, 2808875785498079103090315
    );
    let msg_hash = BigInt3(
        65165253943959161495021481, 38759699917789413779056750, 1848198556339991
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_231_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        44350427382472432114976898, 76208045579507388145581012, 11846512745009743071758189
    );
    let s = BigInt3(
        50553203429130033895402546, 37328269535424326762631652, 695541716373770328698994
    );
    let msg_hash = BigInt3(
        37346818326038015995481489, 1009577105086973226580717, 8689154328482431891744198
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_232_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        25688051018064061665946179, 20897495058953396061960835, 8742217607390387299702806
    );
    let s = BigInt3(
        9321731845058019780494900, 42294281233700433974322510, 3581823576174849751890813
    );
    let msg_hash = BigInt3(
        52280642134970036687757381, 53879769940536438663113399, 16769713676480494104872501
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_233_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        65525066104724776097129437, 73433516318197411502280257, 14482078288868348504739757
    );
    let s = BigInt3(
        34051492696283847021067835, 1677377513962593523576537, 14343687982790739245825069
    );
    let msg_hash = BigInt3(
        13947608261708506835992992, 23814442629645084625364322, 7832959078592459942688412
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_234_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        13400135815237068981916365, 72623267680310765894151258, 2439867269963185946935179
    );
    let s = BigInt3(
        40468123015317413529422674, 35545880994348033865499071, 6180660101615046188974186
    );
    let msg_hash = BigInt3(
        56711007653939776011309519, 57726065607397008517627028, 12296757865032892161682813
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_235_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        25350641136438938583345667, 51473213557956620547552332, 17937572670603880934892500
    );
    let s = BigInt3(
        35424439856301359531575495, 10542154555828782586985913, 11619994043532388666021028
    );
    let msg_hash = BigInt3(
        39316083617670047411932773, 35632785207038742369164357, 4029626858438824057376286
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_236_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        15431519325128998673383723, 23918005229989114741817487, 456722990272137346456020
    );
    let s = BigInt3(
        62800047959159661385299472, 41768624990789874695287547, 10660866861722459528559815
    );
    let msg_hash = BigInt3(
        20302415542813575046665820, 31811783426631048381411967, 11743588946699218854084610
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_237_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        23919139872109172662633245, 50646547776234924451672908, 12045244160463338878422394
    );
    let s = BigInt3(
        33629706084818830286035202, 20796301675130054081747373, 13480765989626882896203977
    );
    let msg_hash = BigInt3(
        8597814632925589201092998, 4369820424478189159360839, 10293250475899137527119872
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_238_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        15621487474243611205244599, 15528756636658965665245274, 12216471314328209572736303
    );
    let s = BigInt3(
        20064585547803317566991132, 26805866852942622079617951, 2468160521521252016544978
    );
    let msg_hash = BigInt3(
        64070486039132972175395750, 72198120700569782334, 12225724247102652129738752
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_239_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        5126846161659894017113529, 46438703252618293200372206, 19174880884406786114787948
    );
    let s = BigInt3(
        68655546918883430990222160, 52272274264772790791417857, 4681401553911467138579230
    );
    let msg_hash = BigInt3(
        56231216054611520619708500, 16199815495094913699, 10778199987155804564828160
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_240_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        4606927751281250301044341, 74545822769232362658959129, 13682654608856369618314551
    );
    let s = BigInt3(
        24516675649587426480291826, 16617739884883651377192997, 15989929466808517042208213
    );
    let msg_hash = BigInt3(
        67501756517873024598209285, 152642284941540014, 7708507917668999648408384
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_241_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        11106132379087675448094888, 46030415718597826184195801, 4471120695625593898855607
    );
    let s = BigInt3(
        67012313289979297674138200, 56993151191861793034545943, 5788287700555564065875218
    );
    let msg_hash = BigInt3(
        69833161603217351572360244, 38685626228695304409436531, 15736740337658580154441192
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_242_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        40703947637153005050301903, 22654733179311713176800062, 3685951397808593672094193
    );
    let s = BigInt3(
        57804386176993591279646701, 44349435174544066735732879, 5421676040800348669773222
    );
    let msg_hash = BigInt3(
        59263831068302812997166991, 77050131534501349205305733, 14323052845559984496839917
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_243_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        16831628515399660622712658, 26841812994933271409046618, 4262064810402787915187259
    );
    let s = BigInt3(
        51138354663866727391680125, 29645244314743953005702521, 490761459198358769459222
    );
    let msg_hash = BigInt3(
        2140620992986234475809395, 5481044173133185803303628, 3863959149695341675483876
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_244_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        56235326058973704971843023, 27955440705034147432013783, 5186304672155168413077442
    );
    let s = BigInt3(
        49943832359073028773076614, 37445058115758867270106460, 3421615235294536453447112
    );
    let msg_hash = BigInt3(
        31567804598923694507555569, 23703428569124726273446536, 13965900508492870001440349
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_245_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        51441679942961529743640809, 31323278485465722915311318, 3470159408038576180367865
    );
    let s = BigInt3(
        55758252477025054415653113, 33757424024281534045818018, 9470580048191425876180932
    );
    let msg_hash = BigInt3(
        63019302834527084651075658, 14965091926560941960915081, 103962649840233748250607
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_246_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        17845638874236480151980943, 59184351253793311512326992, 14331934704823739088829755
    );
    let s = BigInt3(
        29738201666500572773008327, 33525251704878128828071628, 18653238291916894814384144
    );
    let msg_hash = BigInt3(
        12010466957845224056910691, 876955454369575668285750, 11987313774256818462497194
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_247_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        49975958157734533790822854, 45183602311308804973519205, 6118347983555249338459936
    );
    let s = BigInt3(
        45467879106977299503007526, 75759426982522694166614086, 16245893061390047164008926
    );
    let msg_hash = BigInt3(
        42285765908796141461680524, 44562168889335563811815427, 15730818019333291976856471
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_248_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        19464021954034469015684621, 31020602100004372970362327, 18592697048066912126341216
    );
    let s = BigInt3(
        59715010344942501863559151, 42006782122826450156525036, 4803651412918582478593705
    );
    let msg_hash = BigInt3(
        623518207113527975721748, 75027791939445322476945408, 3663369674109617152051275
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_249_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        12039287060632347623303802, 28305470098586526239699045, 11259860334100809105839067
    );
    let s = BigInt3(
        52271770727705583766229025, 61857597008460916003795684, 14964351083546369370685374
    );
    let msg_hash = BigInt3(
        4218492299325433882296, 63897975427752075606360064, 14107411499279572580643620
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_250_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        28043519579671539518558589, 50614899677796415023330524, 14191135248596341707604966
    );
    let s = BigInt3(
        49481921439162431092559616, 5768068149256488216817559, 11904557701611766876178393
    );
    let msg_hash = BigInt3(
        14103137791335850334, 65286050745311162978364416, 16073247588633385844494168
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_251_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        26115587034612799530545790, 31518048601433111031692253, 3535122510187476989013671
    );
    let s = BigInt3(
        48014085084335972718581880, 62721163688818387061441840, 9270726966140665937199612
    );
    let msg_hash = BigInt3(
        36062091483907297, 75558565913846506796002292, 9217203650722180065339889
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_252_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        41252127427703093925514329, 76249329643472152578969996, 6415163615416093073122983
    );
    let s = BigInt3(
        40000239421192831170103549, 61810412565102162007060587, 3523022055355998807490241
    );
    let msg_hash = BigInt3(
        61655216800525852263582938, 50095270422354944513141541, 10590237217024509954685355
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_253_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        33722327991840722601677926, 18179884287763615505673946, 6238798009120240499936878
    );
    let s = BigInt3(
        50704247193963395717021123, 13209514785239009376456892, 7694797519584041178553240
    );
    let msg_hash = BigInt3(
        67142606653440874009750305, 76157019746141340063079183, 1108253164482935249272894
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_254_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        52366207884282480811438343, 66595917511570128915918943, 2453917624742861526561817
    );
    let s = BigInt3(
        18539485283832333029943143, 54152582216110919099620943, 15559741721026266077056640
    );
    let msg_hash = BigInt3(
        23594935196776711067859101, 46466913574860010311869880, 16936498544486232547657347
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_255_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        31480323443529089504933672, 60834796686853972792568021, 7656400244826355324433034
    );
    let s = BigInt3(
        73196173698915379457620265, 68047641049730978828303034, 13194307960346887996609761
    );
    let msg_hash = BigInt3(
        35060722986845172588641761, 48786509208134226779188194, 11990309105352338695099625
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_256_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        12752163386262546628410876, 74684853717967579271058272, 12489571432410862586691334
    );
    let s = BigInt3(
        71102808942101888580655885, 6790122404304121300909337, 17650949804137520214482896
    );
    let msg_hash = BigInt3(
        31017303839471022930709781, 72788081337289458588003663, 7455078139166631695401492
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_257_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        62746587043837808869605039, 73824760614843914389120196, 11436343856839417291540977
    );
    let s = BigInt3(
        10951955086214901447890466, 44714519265684220886975480, 9646164676766726332490775
    );
    let msg_hash = BigInt3(
        13792063760150180864721096, 20385489116083120791440297, 4184210338287053005859246
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_258_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        57656358972013021531179102, 63747003301992431846951958, 6541850673586925530674863
    );
    let s = BigInt3(
        58937536064964934917470884, 71330072311870682899247585, 1057715120201869433505053
    );
    let msg_hash = BigInt3(
        66252970586538897754292224, 9851744376981240433277600, 1029662461725513408021327
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_259_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        21865162623384498845195174, 49109174109140843195296355, 12146828755704019415681384
    );
    let s = BigInt3(
        20898400223326957855720249, 30215908867035796368625942, 7123399679955197805050612
    );
    let msg_hash = BigInt3(
        10207776149548249557837978, 26136748192324451925744854, 19342813110055631278081789
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_260_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        29829513490069775959300744, 846833327889754556659051, 7352328345746337672582966
    );
    let s = BigInt3(
        49906783696028606354198575, 39880298641857464793447002, 8725983682539635681860481
    );
    let msg_hash = BigInt3(
        48263435053821705136367543, 20658025292324856780632964, 9369175101998220995083267
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_261_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        77164531960780866539045626, 14091592731319598496670714, 14407173684771756646126587
    );
    let s = BigInt3(
        62504656408841957091405354, 26929281639851381346960445, 8137097097326239811881683
    );
    let msg_hash = BigInt3(
        47017798949056929595368341, 25226145505435930131732490, 12294090842340757158042376
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_262_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        47166579456033260939360978, 65827891157868303103491204, 5560039218400977719479737
    );
    let s = BigInt3(
        7606581046924043146090131, 2674593890344224085082274, 5043920682494352909406993
    );
    let msg_hash = BigInt3(
        16044950002011053956473024, 50152232969448547192232476, 7561145151744844814727535
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_263_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        66153793219400550357322162, 38805701880119867515837011, 675717496614947533515308
    );
    let s = BigInt3(
        31071314342705555757451822, 55027133721387680017482766, 11892198415389421527663987
    );
    let msg_hash = BigInt3(
        64083279718252515613872011, 18794752904940688566944861, 11297106407277624645302992
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_264_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        31115247244518377386718712, 13859674903076264820231732, 14367250203886821662891479
    );
    let s = BigInt3(
        49915482450526477028383881, 10487032615563772394028517, 17064754571161577115057935
    );
    let msg_hash = BigInt3(
        72426853270091733245632760, 5009635021307761346220935, 18273453379862992603050280
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_265_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        12868302416924138411000899, 60787040054102605733333621, 1655014787057000541200458
    );
    let s = BigInt3(
        40194832189687826543251747, 64880169257163847465404571, 17476654578296999079392123
    );
    let msg_hash = BigInt3(
        37433932166604276352884207, 2270116649436264761990913, 691689920627213009420273
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_266_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        33848762183302850146299309, 46022985439023810910221559, 4018378002354112110503007
    );
    let s = BigInt3(
        2836694877977053322322886, 59582303742631929999766346, 1457107926026204872580357
    );
    let msg_hash = BigInt3(
        64842927509202846989419913, 74031591761517095234050302, 7296196317010178764439551
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_267_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        54691592555688453077293307, 46093447298894096172616999, 5610319074918559911551194
    );
    let s = BigInt3(
        2852178676915480118318978, 73294888419238575420515478, 4404112050435513642382853
    );
    let msg_hash = BigInt3(
        66388969740550266807837154, 77353171237879279183713304, 15035749153396846354235391
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_268_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        33877259144206508451307158, 13004849164352620759790101, 17740858778540459171167809
    );
    let s = BigInt3(
        66257606298021815004755665, 11920766932351587983799600, 8788856161382162663759320
    );
    let msg_hash = BigInt3(
        3718219617462493002589837, 77371215692987346069052209, 16774735916065686150406143
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_269_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        3238185229099441256362066, 38641603623282744525882658, 3587336727278370847404278
    );
    let s = BigInt3(
        31756046383296537165472012, 3376310037428446436791345, 13019095732989341709126347
    );
    let msg_hash = BigInt3(
        13416307604841896140785407, 77371252444958635534273835, 8391127483520058358151311
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_270_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        65441430189875879123878425, 72811060993706923852290337, 19327949719482409334073312
    );
    let s = BigInt3(
        47969076250973691872257178, 52561055096783889714527277, 9186048896166066876414889
    );
    let msg_hash = BigInt3(
        34673923780913117580589753, 9671406556628015904810103, 15542869112344307389657229
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_271_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        45375790782499564638058920, 60677671975926819784092366, 9818452022499215615972328
    );
    let s = BigInt3(
        18113217689917995091444480, 28115524384321698040014835, 15522246108740938426810217
    );
    let msg_hash = BigInt3(
        34225814908350230192391300, 41632382912977140136942343, 3343185256248820729241417
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_272_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        74951736282855324061050888, 33756010181645559627597467, 16908653769292479114174809
    );
    let s = BigInt3(
        10907258258291480267231463, 16397104306279199101121001, 344202336421569451889282
    );
    let msg_hash = BigInt3(
        31934625503660092936811537, 25379989727301423017190015, 13003322330317477145398141
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_273_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        49806624636918678954858338, 3408097030897779704303183, 13071989412918577706499495
    );
    let s = BigInt3(
        10762618804352053688243013, 66400089119168373148399654, 11121780331582276439979115
    );
    let msg_hash = BigInt3(
        49053143611971590863906320, 24011736496818413896463608, 6013372214137750640337929
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_274_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        76766787147288871339563139, 42578174415295421160813818, 13033905026239845909673191
    );
    let s = BigInt3(
        41223614530931468563363752, 75063308572475461654445107, 18571351033420789294748874
    );
    let msg_hash = BigInt3(
        67416541148215335751239514, 63805330709491465376866231, 5000546427185684611189793
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_275_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        35622734945335756766024439, 34126182006614092892466670, 7818815300360626455417755
    );
    let s = BigInt3(
        37462748574319379951770453, 37214552806628476763159456, 8107021592742976135573552
    );
    let msg_hash = BigInt3(
        76920343528733549614452760, 12693073447460948552974335, 8497255470074947247204275
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_276_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        3693462862567321766449072, 42949276716230885373334239, 5411276195999809903229370
    );
    let s = BigInt3(
        69496542524304727096370243, 22458420681716550895575527, 10998236918122514861248355
    );
    let msg_hash = BigInt3(
        77371247953001865975790229, 26973737639829533972167679, 4571507085910649529254973
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_277_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        53631689473097293035118755, 72556084246589485208644682, 5128430989409039636339288
    );
    let s = BigInt3(
        68831335860569132561373042, 44507592519088225293313645, 2247316077389111516517828
    );
    let msg_hash = BigInt3(
        77371252439450981261161371, 73695590731155671251067703, 16783720871854655476957374
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_278_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        31216801894572198857539345, 38170640856643502270979849, 6878619527816930376240252
    );
    let s = BigInt3(
        76806261723048938125856117, 65297857825680699090507396, 5267775917712402908846313
    );
    let msg_hash = BigInt3(
        12089258195916627755108380, 45377197972609279244729802, 10834834820543316983565781
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_279_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        54373347618104401268236399, 27969367106739512078326825, 7148219802708852308537996
    );
    let s = BigInt3(
        6060996326884602810010656, 56684316584842621445996367, 13389690278176037635019618
    );
    let msg_hash = BigInt3(
        46902543907861294729673896, 49423686593692134886619664, 8114180445470117580595390
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_280_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        27894849454096231914074926, 2891136387226177843248489, 486884121307694182474491
    );
    let s = BigInt3(
        74121577687567923699476812, 58982784601823552324894550, 16554337251088762508122809
    );
    let msg_hash = BigInt3(
        34485560856501500224098606, 10148683358359726286026898, 19052430913322992394792309
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_281_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        22977480802016692803014714, 53297856082290328058093927, 8950056224398789004721595
    );
    let s = BigInt3(
        1586368687565467188018556, 65856568883766169177490921, 4667780115445497833490110
    );
    let msg_hash = BigInt3(
        15618472507678790275555850, 23849024603770882647872698, 1394191443141454503669252
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_282_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        54703664914256021691372213, 24341344391083996536642317, 9598307014697079101137192
    );
    let s = BigInt3(
        55070755979082970251893387, 7504419858448315861118252, 2764671185471484171797917
    );
    let msg_hash = BigInt3(
        27682567323355259458289518, 59957714409999880132920686, 678644572859289204475238
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}

@view
func test_283_special_case_hash{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    let public_key_pt = EcPoint(
        BigInt3(66530477520657471088306232, 31283912406988747838219367, 3109587271018297924898788),
        BigInt3(19349113621168673691619646, 6224844839444817491486113, 15071572588068884390158843),
    );
    let r = BigInt3(
        51258994497534204093952840, 46215970556021125624704790, 10978441364091325831218803
    );
    let s = BigInt3(
        52252224884003743147951338, 17757968571084647373189380, 18891614113339012494431550
    );
    let msg_hash = BigInt3(
        28824387176412821457993727, 76372076752896222163751482, 16137084660919569725552405
    );
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s);
    return ();
}
