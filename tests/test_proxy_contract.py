import hashlib
import secrets

from eth_utils import to_tuple, keccak
from py_ecc.bls.g2_primatives import pubkey_to_G1, signature_to_G2
from py_ecc.bls.hash import expand_message_xmd
from py_ecc.bls.hash_to_curve import (
    clear_cofactor_G2,
    hash_to_field_FQ2,
    hash_to_G2,
    map_to_curve_G2,
)
from py_ecc.bls import G2ProofOfPossession
from py_ecc.optimized_bls12_381 import FQ2, normalize

EMPTY_DEPOSIT_ROOT = "d70a234731285c6804c2a4f56711ddb8c82c99740f207854891028af34e27e5e"
DEPOSIT_EVENT_SIGNATURE = "DepositEvent(bytes,bytes,bytes,bytes,bytes)".encode()
DEPOSIT_EVENT_TOPIC = keccak(DEPOSIT_EVENT_SIGNATURE)


def test_compute_signing_root_matches_spec(
    proxy_contract, bls_public_key, withdrawal_credentials, deposit_amount, signing_root
):
    amount_in_wei = deposit_amount * 10 ** 9
    computed_signing_root = proxy_contract.functions.computeSigningRoot(
        bls_public_key, withdrawal_credentials, amount_in_wei
    ).call()

    assert computed_signing_root == signing_root


def test_expand_message_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.expandMessage(signing_root).call()

    spec_result = expand_message_xmd(signing_root, dst, 256, hashlib.sha256)

    assert result == spec_result


def _convert_int_to_fp_repr(field_element):
    element_as_bytes = int(field_element).to_bytes(48, byteorder="big")
    a_bytes = element_as_bytes[:16]
    b_bytes = element_as_bytes[16:]
    return (
        int.from_bytes(a_bytes, byteorder="big"),
        int.from_bytes(b_bytes, byteorder="big"),
    )


@to_tuple
def _convert_int_to_fp2_repr(field_element):
    for coeff in field_element.coeffs:
        yield _convert_int_to_fp_repr(coeff)


def _convert_fp_to_int(fp_repr):
    a, b = fp_repr
    a_bytes = a.to_bytes(16, byteorder="big")
    b_bytes = b.to_bytes(32, byteorder="big")
    full_bytes = b"".join((a_bytes, b_bytes))
    return int.from_bytes(full_bytes, byteorder="big")


def _convert_fp2_to_int(fp2_repr):
    a, b = fp2_repr
    return FQ2((_convert_fp_to_int(a), _convert_fp_to_int(b)))


def test_hash_to_field_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToField(signing_root).call()
    converted_result = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in result)

    spec_result = hash_to_field_FQ2(signing_root, 2, dst, hashlib.sha256)

    assert converted_result == spec_result


def test_map_to_curve_matches_spec(proxy_contract, signing_root):
    field_elements_parts = proxy_contract.functions.hashToField(signing_root).call()
    field_elements = tuple(
        _convert_fp2_to_int(fp2_repr) for fp2_repr in field_elements_parts
    )

    # NOTE: mapToCurve (called below) precompile includes "clearing the cofactor"
    first_group_element = normalize(
        clear_cofactor_G2(map_to_curve_G2(field_elements[0]))
    )

    computed_first_group_element_parts = proxy_contract.functions.mapToCurve(
        field_elements_parts[0]
    ).call()
    computed_first_group_element = tuple(
        _convert_fp2_to_int(fp2_repr) for fp2_repr in computed_first_group_element_parts
    )
    assert computed_first_group_element == first_group_element

    second_group_element = normalize(
        clear_cofactor_G2(map_to_curve_G2(field_elements[1]))
    )

    computed_second_group_element_parts = proxy_contract.functions.mapToCurve(
        field_elements_parts[1]
    ).call()
    computed_second_group_element = tuple(
        _convert_fp2_to_int(fp2_repr)
        for fp2_repr in computed_second_group_element_parts
    )
    assert computed_second_group_element == second_group_element


def test_hash_to_curve_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToCurve(signing_root).call()
    converted_result = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in result)

    spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))

    assert converted_result == spec_result


def test_bls_pairing_check(proxy_contract, signing_root, bls_public_key, signature):
    public_key_point = pubkey_to_G1(bls_public_key)
    public_key = normalize(public_key_point)
    public_key_repr = (
        _convert_int_to_fp_repr(public_key[0]),
        _convert_int_to_fp_repr(public_key[1]),
    )

    # skip some data wrangling by calling contract function for this...
    message_on_curve = proxy_contract.functions.hashToCurve(signing_root).call()

    projective_signature_point = signature_to_G2(signature)
    signature_point = normalize(projective_signature_point)
    signature_repr = (
        _convert_int_to_fp2_repr(signature_point[0]),
        _convert_int_to_fp2_repr(signature_point[1]),
    )
    assert proxy_contract.functions.blsPairingCheck(
        public_key_repr, message_on_curve, signature_repr
    ).call()


def test_bls_signature_is_valid_works_with_valid_signature(
    proxy_contract,
    bls_public_key,
    signing_root,
    signature,
    public_key_witness,
    signature_witness,
):
    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)

    assert proxy_contract.functions.blsSignatureIsValid(
        signing_root,
        bls_public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()


def test_bls_signature_is_valid_fails_with_invalid_message(
    proxy_contract,
    bls_public_key,
    signing_root,
    signature,
    public_key_witness,
    signature_witness,
):
    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)

    message = b"\x01" + signing_root[1:]
    assert message != signing_root

    assert not proxy_contract.functions.blsSignatureIsValid(
        message,
        bls_public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()


def test_bls_signature_is_valid_fails_with_invalid_public_key(
    proxy_contract, seed, signing_root, signature, signature_witness
):
    another_seed = "another-secret".encode()
    assert seed != another_seed
    another_private_key = G2ProofOfPossession.KeyGen(another_seed)
    public_key = G2ProofOfPossession.SkToPk(another_private_key)

    group_element = pubkey_to_G1(public_key)
    normalized_group_element = normalize(group_element)
    public_key_witness = normalized_group_element[1]
    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)

    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)

    assert not proxy_contract.functions.blsSignatureIsValid(
        signing_root,
        public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()


def test_bls_signature_is_valid_fails_with_invalid_signature(
    proxy_contract, bls_public_key, signing_root, public_key_witness, bls_private_key
):
    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)

    another_message = hashlib.sha256(b"not the signing root").digest()
    assert signing_root != another_message
    signature = G2ProofOfPossession.Sign(bls_private_key, another_message)
    group_element = signature_to_G2(signature)
    normalized_group_element = normalize(group_element)
    signature_witness = normalized_group_element[1]

    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)

    assert not proxy_contract.functions.blsSignatureIsValid(
        signing_root,
        bls_public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()


def test_deposit_works(
    deposit_contract,
    bls_public_key,
    withdrawal_credentials,
    signature,
    deposit_data_root,
    deposit_amount,
    w3,
):
    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )
    assert (
        deposit_contract.functions.get_deposit_root().call().hex() == EMPTY_DEPOSIT_ROOT
    )

    amount_in_wei = deposit_amount * 10 ** 9
    deposit_contract.functions.deposit(
        bls_public_key, withdrawal_credentials, signature, deposit_data_root
    ).transact({"value": amount_in_wei, "gas": 10 ** 6})

    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 1
    )


def test_verify_and_deposit(
    proxy_contract,
    deposit_contract,
    bls_public_key,
    withdrawal_credentials,
    signature,
    deposit_data_root,
    public_key_witness,
    signature_witness,
    deposit_amount,
    w3,
):
    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )
    assert (
        deposit_contract.functions.get_deposit_root().call().hex() == EMPTY_DEPOSIT_ROOT
    )

    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)
    amount_in_wei = deposit_amount * 10 ** 9
    txn_hash = proxy_contract.functions.verifyAndDeposit(
        bls_public_key,
        withdrawal_credentials,
        signature,
        deposit_data_root,
        public_key_witness_repr,
        signature_witness_repr,
    ).transact({"value": amount_in_wei})

    txn_receipt = w3.eth.getTransactionReceipt(txn_hash)
    block_hash = txn_receipt.blockHash

    log = deposit_contract.events.DepositEvent().getLogs()[0]
    # sanity check
    assert log.blockHash == block_hash

    args = log.args
    assert args.pubkey == bls_public_key
    assert args.withdrawal_credentials == withdrawal_credentials
    assert int.from_bytes(args.amount, byteorder="little") == deposit_amount
    assert args.signature == signature
    assert int.from_bytes(args.index, byteorder="little") == 0

    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 1
    )


def test_verify_and_deposit_fails_with_short_public_key(
    proxy_contract,
    deposit_contract,
    bls_public_key,
    withdrawal_credentials,
    signature,
    deposit_data_root,
    public_key_witness,
    signature_witness,
    deposit_amount,
    assert_tx_failed,
):
    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )

    assert (
        deposit_contract.functions.get_deposit_root().call().hex() == EMPTY_DEPOSIT_ROOT
    )

    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)
    amount_in_wei = deposit_amount * 10 ** 9
    txn = proxy_contract.functions.verifyAndDeposit(
        bls_public_key[1:],
        withdrawal_credentials,
        signature,
        deposit_data_root,
        public_key_witness_repr,
        signature_witness_repr,
    )
    assert_tx_failed(lambda: txn.transact({"value": amount_in_wei}))

    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )


def test_verify_and_deposit_fails_with_short_signature(
    proxy_contract,
    deposit_contract,
    bls_public_key,
    withdrawal_credentials,
    signature,
    deposit_data_root,
    public_key_witness,
    signature_witness,
    deposit_amount,
    assert_tx_failed,
):
    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )
    assert (
        deposit_contract.functions.get_deposit_root().call().hex() == EMPTY_DEPOSIT_ROOT
    )

    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)
    amount_in_wei = deposit_amount * 10 ** 9
    txn = proxy_contract.functions.verifyAndDeposit(
        bls_public_key,
        withdrawal_credentials,
        signature[1:],
        deposit_data_root,
        public_key_witness_repr,
        signature_witness_repr,
    )
    assert_tx_failed(lambda: txn.transact({"value": amount_in_wei}))

    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )


def test_verify_and_deposit_fails_with_incorrect_message_via_withdrawal_credentials(
    proxy_contract,
    deposit_contract,
    bls_public_key,
    withdrawal_credentials,
    signature,
    deposit_data_root,
    public_key_witness,
    signature_witness,
    deposit_amount,
    assert_tx_failed,
):
    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )
    assert (
        deposit_contract.functions.get_deposit_root().call().hex() == EMPTY_DEPOSIT_ROOT
    )

    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)
    amount_in_wei = deposit_amount * 10 ** 9
    # NOTE: we modify the ``withdrawal_credentials`` to induce an incorrect message for the given
    # public key and signature
    txn = proxy_contract.functions.verifyAndDeposit(
        bls_public_key,
        withdrawal_credentials[1:],
        signature,
        deposit_data_root,
        public_key_witness_repr,
        signature_witness_repr,
    )
    assert_tx_failed(lambda: txn.transact({"value": amount_in_wei}))

    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )


def test_verify_and_deposit_fails_with_incorrect_message_via_msg_value(
    proxy_contract,
    deposit_contract,
    bls_public_key,
    withdrawal_credentials,
    signature,
    deposit_data_root,
    public_key_witness,
    signature_witness,
    deposit_amount,
    assert_tx_failed,
):
    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )
    assert (
        deposit_contract.functions.get_deposit_root().call().hex() == EMPTY_DEPOSIT_ROOT
    )

    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)
    amount_in_wei = deposit_amount * 10 ** 9
    txn = proxy_contract.functions.verifyAndDeposit(
        bls_public_key,
        withdrawal_credentials,
        signature,
        deposit_data_root,
        public_key_witness_repr,
        signature_witness_repr,
    )
    # NOTE: we modify the `msg.value` to induce an incorrect message for the given
    # public key and signature
    assert_tx_failed(lambda: txn.transact({"value": amount_in_wei - 1}))

    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )


def test_verify_and_deposit_fails_with_incorrect_public_key(
    proxy_contract,
    deposit_contract,
    withdrawal_credentials,
    signature,
    deposit_data_root,
    public_key_witness,
    signature_witness,
    deposit_amount,
    assert_tx_failed,
    seed,
):
    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )
    assert (
        deposit_contract.functions.get_deposit_root().call().hex() == EMPTY_DEPOSIT_ROOT
    )

    another_seed = "another-secret".encode()
    assert seed != another_seed
    another_private_key = G2ProofOfPossession.KeyGen(another_seed)
    public_key = G2ProofOfPossession.SkToPk(another_private_key)

    group_element = pubkey_to_G1(public_key)
    normalized_group_element = normalize(group_element)
    public_key_witness = normalized_group_element[1]
    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)
    amount_in_wei = deposit_amount * 10 ** 9
    txn = proxy_contract.functions.verifyAndDeposit(
        public_key,
        withdrawal_credentials,
        signature,
        deposit_data_root,
        public_key_witness_repr,
        signature_witness_repr,
    )
    assert_tx_failed(lambda: txn.transact({"value": amount_in_wei}))

    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )


def test_verify_and_deposit_fails_with_incorrect_signature(
    proxy_contract,
    deposit_contract,
    bls_public_key,
    withdrawal_credentials,
    signature,
    deposit_data_root,
    public_key_witness,
    signature_witness,
    deposit_amount,
    assert_tx_failed,
    signing_root,
    bls_private_key,
):
    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )
    assert (
        deposit_contract.functions.get_deposit_root().call().hex() == EMPTY_DEPOSIT_ROOT
    )

    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)

    another_message = hashlib.sha256(b"not the signing root").digest()
    assert signing_root != another_message
    signature = G2ProofOfPossession.Sign(bls_private_key, another_message)
    group_element = signature_to_G2(signature)
    normalized_group_element = normalize(group_element)
    signature_witness = normalized_group_element[1]
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)

    amount_in_wei = deposit_amount * 10 ** 9
    txn = proxy_contract.functions.verifyAndDeposit(
        bls_public_key,
        withdrawal_credentials,
        signature,
        deposit_data_root,
        public_key_witness_repr,
        signature_witness_repr,
    )
    assert_tx_failed(lambda: txn.transact({"value": amount_in_wei}))

    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )


def test_verify_and_deposit_fails_with_incorrect_deposit_data_root(
    proxy_contract,
    deposit_contract,
    bls_public_key,
    withdrawal_credentials,
    signature,
    deposit_data_root,
    public_key_witness,
    signature_witness,
    deposit_amount,
    assert_tx_failed,
):
    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )

    assert (
        deposit_contract.functions.get_deposit_root().call().hex() == EMPTY_DEPOSIT_ROOT
    )

    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)
    amount_in_wei = deposit_amount * 10 ** 9
    random_bytes = secrets.token_bytes(32)
    assert random_bytes != deposit_data_root
    txn = proxy_contract.functions.verifyAndDeposit(
        bls_public_key,
        withdrawal_credentials,
        signature,
        random_bytes,
        public_key_witness_repr,
        signature_witness_repr,
    )
    assert_tx_failed(lambda: txn.transact({"value": amount_in_wei}))

    assert (
        int.from_bytes(
            deposit_contract.functions.get_deposit_count().call(), byteorder="little"
        )
        == 0
    )
