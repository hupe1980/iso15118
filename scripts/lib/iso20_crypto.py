"""Mint ISO 15118-20 envelope and Ed448 vectors with an independent implementation.

Run by scripts/make-test-pki.sh (python3 -I). Everything but one value comes from
`cryptography` (OpenSSL-backed): P-521 and X448 ECDH, the concatenation KDF with
SHA-512, AES-GCM-256, Ed448 signatures, SHAKE256. The exception is the X448-path
key check [V2G20-2510] — scalar times the edwards448 base point — which no
OpenSSL API exposes; it uses RFC 8032 §5.2's reference arithmetic below.

Every input is fixed, so the outputs are reproducible.

Usage: python3 -I iso20_crypto.py OUT_DIR
"""

import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, x448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)

PCID = b"WMIV1234567890ABC1"  # 18 ASCII [V2G20-2492]
SKI = bytes.fromhex("0123456789ABCDEF")  # 8 bytes
AAD = PCID + SKI.hex().upper().encode()
IV = bytes.fromhex("000102030405060708090A0B")


def write(name, data):
    (OUT / name).write_bytes(data)


def session_key(z):
    # NIST SP 800-56A concatenation KDF, SHA-512, OtherInfo 01 'U' 'V' [V2G20-2535]
    return ConcatKDFHash(algorithm=hashes.SHA512(), length=32, otherinfo=b"\x01UV").derive(z)


def p521_private(seed_byte):
    scalar = int.from_bytes(bytes([seed_byte]) * 65, "big")
    return ec.derive_private_key(scalar, ec.SECP521R1())


def point(key):
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


# --- SECP521_EncryptedPrivateKey -------------------------------------------
oem = p521_private(0x11)          # the vehicle's OEM provisioning key (static)
ephemeral = p521_private(0x22)    # the SA's ephemeral key
contract = p521_private(0x33)     # the contract key to deliver
contract_scalar = contract.private_numbers().private_value.to_bytes(66, "big")
z = ephemeral.exchange(ec.ECDH(), oem.public_key())
sealed = AESGCM(session_key(z)).encrypt(IV, contract_scalar, AAD)
write("secp521-oem-private.bin", oem.private_numbers().private_value.to_bytes(66, "big"))
write("secp521-oem-public.bin", point(oem))
write("secp521-ephemeral-private.bin", ephemeral.private_numbers().private_value.to_bytes(66, "big"))
write("secp521-dh-public-key.bin", point(ephemeral))           # 133 bytes, 04 ‖ X ‖ Y
write("secp521-field.bin", IV + sealed)                          # 12 + 66 + 16
write("secp521-contract-private.bin", contract_scalar)
write("secp521-contract-public.bin", point(contract))
write("secp521-session-key.bin", session_key(z))

# --- X448_EncryptedPrivateKey ------------------------------------------------
oem_x = x448.X448PrivateKey.from_private_bytes(bytes([0x44]) * 56)
eph_x = x448.X448PrivateKey.from_private_bytes(bytes([0x55]) * 56)
raw = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
zx = eph_x.exchange(oem_x.public_key())
# A 448-bit contract scalar below the edwards448 order, little-endian.
L = 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
contract_x_int = (int.from_bytes(bytes([0x66]) * 56, "little")) % L
contract_x = contract_x_int.to_bytes(56, "little")
sealed_x = AESGCM(session_key(zx)).encrypt(IV, contract_x, AAD)
write("x448-oem-private.bin", oem_x.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
write("x448-oem-public.bin", raw(oem_x))
write("x448-ephemeral-private.bin", bytes([0x55]) * 56)
write("x448-dh-public-key.bin", b"\x00" + raw(eph_x))           # 57 bytes [V2G20-2532]
write("x448-field.bin", IV + sealed_x)                           # 12 + 56 + 16
write("x448-contract-private.bin", contract_x)

# RFC 8032 §5.2 reference arithmetic: edwards448, scalar times B, encoded.
p = 2**448 - 2**224 - 1
d = -39081


def inv(x):
    return pow(x, p - 2, p)


def add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    xy = d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + y1 * x2) * inv(1 + xy) % p
    y3 = (y1 * y2 - x1 * x2) * inv(1 - xy) % p
    return (x3, y3)


def mul(s, P):
    Q = (0, 1)
    while s:
        if s & 1:
            Q = add(Q, P)
        P = add(P, P)
        s >>= 1
    return Q


Bx = 224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710
By = 298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660
x, y = mul(contract_x_int, (Bx, By))
encoded = bytearray(y.to_bytes(57, "little"))
encoded[56] |= (x & 1) << 7
write("x448-contract-public.bin", bytes(encoded))                # what [V2G20-2510] compares

# --- Ed448 and SHAKE256 --------------------------------------------------------
seed = bytes([0x77]) * 57
signer = ed448.Ed448PrivateKey.from_private_bytes(seed)
message = b"ISO 15118-20 Ed448 vector: canonical SignedInfo stands here"
write("ed448-seed.bin", seed)
write("ed448-public.bin", raw(signer))
write("ed448-message.bin", message)
write("ed448-signature.bin", signer.sign(message))                # pure Ed448, 114 bytes
write("shake256-64.bin", hashlib.shake_256(message).digest(64))

# --- TPM 2.0 outer duplication wrapper (§7.9.2.5.3, TPM 2.0 Part 1 §23.3.2) ----
import hmac as hmac_mod
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

try:  # CFB moved to `decrepit` in cryptography 45
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import CFB


def tpm2b(data):
    return len(data).to_bytes(2, "big") + data


def p521_scalar(first, rest):
    return bytes([first]) + bytes([rest]) * 65


storage = ec.derive_private_key(int.from_bytes(p521_scalar(0, 0x33), "big"), ec.SECP521R1())
tpm_contract_scalar = p521_scalar(0, 0x11)
tpm_contract = ec.derive_private_key(int.from_bytes(tpm_contract_scalar, "big"), ec.SECP521R1())
tpm_ephemeral = ec.derive_private_key(int.from_bytes(p521_scalar(0, 0x22), "big"), ec.SECP521R1())
policy = hashlib.sha512(b"an OEM policy").digest()
qs, qc, qe = point(storage), point(tpm_contract), point(tpm_ephemeral)

attributes = (1 << 5) | (1 << 18) | (1 << 7)  # sensitiveDataOrigin | sign | adminWithPolicy
public = (b"\x00\x23\x00\x0d" + attributes.to_bytes(4, "big") + tpm2b(policy)
          + b"\x00\x10\x00\x10\x00\x05\x00\x10" + tpm2b(qc[1:67]) + tpm2b(qc[67:]))
name = b"\x00\x0d" + hashlib.sha512(public).digest()
z = tpm_ephemeral.exchange(ec.ECDH(), storage.public_key())
seed = hashlib.sha512(b"\x00\x00\x00\x01" + z + b"DUPLICATE\x00" + qe[1:67] + qs[1:67]).digest()


def kdfa(key, label, context, bits):
    data = b"\x00\x00\x00\x01" + label + b"\x00" + context + bits.to_bytes(4, "big")
    return hmac_mod.new(key, data, hashlib.sha512).digest()[: bits // 8]


sym_key = kdfa(seed, b"STORAGE", name, 256)
hmac_key = kdfa(seed, b"INTEGRITY", b"", 512)
sensitive = tpm2b(b"\x00\x23" + tpm2b(b"") + tpm2b(b"") + tpm2b(tpm_contract_scalar))
encryptor = Cipher(algorithms.AES(sym_key), CFB(bytes(16))).encryptor()
enc = encryptor.update(sensitive) + encryptor.finalize()
integrity = hmac_mod.new(hmac_key, enc + name, hashlib.sha512).digest()
write("tpm-storage-key.bin", qs[1:])                       # X ‖ Y, 132 bytes
write("tpm-policy-digest.bin", policy)
write("tpm-contract-private.bin", tpm_contract_scalar)
write("tpm-contract-public.bin", qc)
write("tpm-ephemeral-private.bin", p521_scalar(0, 0x22))
write("tpm-encrypted-private-key.bin", tpm2b(integrity) + enc)  # 142 bytes
write("tpm-object-public.bin", tpm2b(public))
