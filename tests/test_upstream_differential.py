"""Reference differential testing between Python and upstream Rust prototype (CCS 2019).

Reference:
    Nirvan Tyagi, Ian Miers, and Thomas Ristenpart.
    "Traceback for End-to-End Encrypted Messaging."
    ACM CCS 2019 / IACR ePrint 2019/981.
    Upstream prototype: https://github.com/nirvantyagi/tracing (commit 24644f73fae82c1f6f4d7daea4f24638ecfd060b)
    Assessment: docs/STAGE2_DIFFERENTIAL_ASSESSMENT.md
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from opentrace.protocols import traceback2019_crypto

ROOT = Path(__file__).resolve().parent.parent


def _load_oracle_vectors() -> Dict[str, Any]:
    vector_path = ROOT / "tests" / "data" / "oracle" / "tyagi2019_rust_oracle_vectors.json"
    assert vector_path.is_file(), f"Oracle vector file missing: {vector_path}"
    with vector_path.open("r", encoding="utf-8") as f:
        data: Dict[str, Any] = json.load(f)
    return data


def test_upstream_rust_oracle_vectors_match_python_crypto() -> None:
    """Verify that Python primitive implementations match the upstream Rust oracle with 100% byte fidelity."""
    vectors = _load_oracle_vectors()
    inputs = vectors["inputs"]
    prims = vectors["primitives"]
    path_proto = vectors["path_protocol"]

    k1 = bytes.fromhex(inputs["key1_hex"])
    k2 = bytes.fromhex(inputs["key2_hex"])
    block = bytes.fromhex(inputs["block_hex"])
    message = inputs["message_utf8"].encode("utf-8")
    wrong_message = inputs["wrong_message_utf8"].encode("utf-8")

    # 1. hash: [0..16] of Sha3_256(message)
    py_hash = hashlib.sha3_256(message).digest()[:16].hex()
    assert py_hash == prims["hash_trunc_sha3_256_hex"], "hash() mismatch with Rust oracle"

    # 2. prf: [0..16] of Sha3_256(k || message)
    py_prf = hashlib.sha3_256(k1 + message).digest()[:16].hex()
    assert py_prf == prims["prf_trunc_sha3_256_hex"], "prf() mismatch with Rust oracle"

    # 3. crprf: HMAC-SHA3-256(k, message)
    py_crprf = hmac.new(k1, message, hashlib.sha3_256).hexdigest()
    assert py_crprf == prims["crprf_hmac_sha3_256_hex"], "crprf() mismatch with Rust oracle"

    # 4. encipher: AES-128-ECB(k1, block)
    cipher_enc = Cipher(algorithms.AES(k1), modes.ECB()).encryptor()
    py_enc = (cipher_enc.update(block) + cipher_enc.finalize()).hex()
    assert py_enc == prims["aes128_encipher_hex"], "encipher() mismatch with Rust oracle"

    # 5. decipher: AES-128-ECB-decrypt(k1, enc) -> block
    cipher_dec = Cipher(algorithms.AES(k1), modes.ECB()).decryptor()
    py_dec = (cipher_dec.update(bytes.fromhex(py_enc)) + cipher_dec.finalize()).hex()
    assert py_dec == prims["aes128_decipher_recovered_hex"], "decipher() mismatch with Rust oracle"
    assert py_dec == inputs["block_hex"]

    # 6. path::new_message: ptr is 16 zero bytes
    assert path_proto["origin_metadata_ptr_hex"] == "00" * 16

    # 7. path::generate_tag (origin)
    cipher_origin = Cipher(algorithms.AES(k1), modes.ECB()).encryptor()
    py_origin_ct = (cipher_origin.update(b"\x00" * 16) + cipher_origin.finalize()).hex()
    assert py_crprf == path_proto["origin_sender_tag"]["addr_hex"]
    assert py_origin_ct == path_proto["origin_sender_tag"]["ct_hex"]

    # 8. path::verify_tag (valid vs wrong message)
    # verify_tag computes crprf(k, m); if equal, returns ptr = k
    assert hmac.new(k1, message, hashlib.sha3_256).hexdigest() == path_proto["origin_sender_tag"]["addr_hex"]
    assert hmac.new(k1, wrong_message, hashlib.sha3_256).hexdigest() != path_proto["origin_sender_tag"]["addr_hex"]

    # 9. path::generate_tag (hop 1 forwarding: encrypts k1 under k2)
    py_crprf_hop1 = hmac.new(k2, message, hashlib.sha3_256).hexdigest()
    cipher_hop1 = Cipher(algorithms.AES(k2), modes.ECB()).encryptor()
    py_hop1_ct = (cipher_hop1.update(k1) + cipher_hop1.finalize()).hex()
    assert py_crprf_hop1 == path_proto["forward_hop1_sender_tag"]["addr_hex"]
    assert py_hop1_ct == path_proto["forward_hop1_sender_tag"]["ct_hex"]


def test_classify_profile_divergences_against_production_python() -> None:
    """Explicitly classify and document all differences between production Python and upstream Rust.

    Per docs/STAGE2_DIFFERENTIAL_ASSESSMENT.md Section 2.4, every divergence between
    the production Python profile and the upstream Rust prototype must be explicitly
    classified as KNOWN_PROFILE_DIVERGENCE, and never conflated with interoperability.
    """
    vectors = _load_oracle_vectors()
    inputs = vectors["inputs"]
    rust_prims = vectors["primitives"]

    message = inputs["message_utf8"].encode("utf-8")

    divergence_matrix = []

    # Divergence 1: Tracing key length (32 bytes in Python vs 16 bytes in Rust)
    py_key_len = traceback2019_crypto.TRACING_KEY_SIZE
    rust_key_len = len(bytes.fromhex(inputs["key1_hex"]))
    if py_key_len != rust_key_len:
        divergence_matrix.append({
            "component": "tracing_key_length",
            "python_profile": f"{py_key_len}_bytes",
            "upstream_rust_profile": f"{rust_key_len}_bytes",
            "classification": "KNOWN_PROFILE_DIVERGENCE",
            "rationale": "Python implementation uses 256-bit symmetric keys per paper Section 4; Rust prototype uses 128-bit keys",
        })

    # Divergence 2: CR-PRF algorithm and domain separation
    # Python uses HMAC-SHA256 with domain prefix; Rust uses HMAC-SHA3-256 without prefix
    k1_16 = bytes.fromhex(inputs["key1_hex"])
    k1_32_padded = k1_16 + b"\x00" * 16
    py_mid = traceback2019_crypto._crprf(k1_32_padded, message).hex()
    rust_mid = rust_prims["crprf_hmac_sha3_256_hex"]
    if py_mid != rust_mid:
        divergence_matrix.append({
            "component": "message_identifier_crprf",
            "python_profile": "HMAC-SHA256 with Tyagi2019-PRF-mid-v1 domain separation",
            "upstream_rust_profile": "HMAC-SHA3-256 without domain prefix",
            "classification": "KNOWN_PROFILE_DIVERGENCE",
            "rationale": "Python implements RFC-style domain separation; Rust prototype executes raw HMAC-SHA3-256",
        })

    # Divergence 3: Predecessor pointer encryption
    # Python uses KDF + AES-128-CTR with zero IV; Rust uses direct AES-128-ECB single-block encryption
    py_kdf_enc = traceback2019_crypto._kdf_enc(k1_32_padded)
    py_ct = traceback2019_crypto._aes_ctr(py_kdf_enc, k1_32_padded).hex()
    rust_ct = rust_prims["aes128_encipher_hex"]
    if py_ct != rust_ct:
        divergence_matrix.append({
            "component": "predecessor_pointer_encryption",
            "python_profile": "AES-128-CTR with HMAC-SHA256 KDF key derivation",
            "upstream_rust_profile": "AES-128-ECB single block encrypt directly under tracing key",
            "classification": "KNOWN_PROFILE_DIVERGENCE",
            "rationale": "Python derives separate K_enc = H(k) and uses CTR stream mode; Rust prototype uses ECB under k directly",
        })

    # Divergence 4: Origin predecessor pointer semantics
    # Python samples fresh random dummy k_prev (Figure 3); Rust initializes ptr to [0; 16]
    divergence_matrix.append({
        "component": "origin_predecessor_pointer",
        "python_profile": "random_dummy_k_prev_sampled_by_origin",
        "upstream_rust_profile": "zero_sentinel_16_bytes",
        "classification": "KNOWN_PROFILE_DIVERGENCE",
        "rationale": "Python implements Figure 3 random termination key; Rust prototype uses fixed 0x00 sentinel",
    })

    # Divergence 5: Participant identities and PKI signatures
    divergence_matrix.append({
        "component": "participant_identity_and_signatures",
        "python_profile": "string_account_uri_with_optional_ed25519_device_pki",
        "upstream_rust_profile": "numeric_u32_identifiers_no_digital_signatures",
        "classification": "KNOWN_PROFILE_DIVERGENCE",
        "rationale": "Python supports human-readable URIs and non-repudiation extension; Rust prototype uses integer u32 routing IDs",
    })

    # Assertions on the classification
    assert len(divergence_matrix) == 5, f"Expected 5 divergence classifications, got {len(divergence_matrix)}"
    for item in divergence_matrix:
        assert item["classification"] == "KNOWN_PROFILE_DIVERGENCE"
        assert item["rationale"]

    # Verify that Python internal test vectors remain internally consistent
    kat_result = traceback2019_crypto._crprf(
        bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
        b"Tyagi 2019 fixed test vector payload",
    ).hex()
    assert kat_result == "9e35b1b5fb0a7dc8f56cb8eb622affc53f2f47e7cad89db802c1c16f727b3482"
