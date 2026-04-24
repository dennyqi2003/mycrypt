#!/usr/bin/env python3
"""
mycrypt.py

Markdown file encryption/decryption tool based on X25519 + ChaCha20-Poly1305.

Commands:
  1) Generate keys
      python mycrypt.py genkey

  2) Encrypt (plain.md -> cipher.md)
      python mycrypt.py encrypt

  3) Decrypt (cipher.md -> plain.md)
      python mycrypt.py decrypt

All file paths default to files in the project root:
  public_key.txt, private_key.txt, plain.md, cipher.md
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


MAGIC = b"MYRSA1"
HKDF_INFO = b"myrsa-x25519-chacha20poly1305-v1"
NONCE_SIZE = 12


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _write_text(path: str | Path, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


def _read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def _derive_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def generate_keys(public_path: str, private_path: str) -> None:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_raw = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_raw = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    _write_text(public_path, _b64e(public_raw) + "\n")
    _write_text(private_path, _b64e(private_raw) + "\n")


def load_public_key(path: str) -> x25519.X25519PublicKey:
    raw = _b64d(_read_text(path).strip())
    if len(raw) != 32:
        raise ValueError("Invalid public key length: must be 32 bytes")
    return x25519.X25519PublicKey.from_public_bytes(raw)


def load_private_key(path: str) -> x25519.X25519PrivateKey:
    raw = _b64d(_read_text(path).strip())
    if len(raw) != 32:
        raise ValueError("Invalid private key length: must be 32 bytes")
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def encrypt_file(input_file: str, output_file: str, public_key_file: str) -> None:
    recipient_public = load_public_key(public_key_file)

    plaintext = Path(input_file).read_bytes()

    eph_private = x25519.X25519PrivateKey.generate()
    eph_public_raw = eph_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    shared_secret = eph_private.exchange(recipient_public)
    key = _derive_key(shared_secret)

    nonce = ChaCha20Poly1305.generate_key()[:NONCE_SIZE]
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext, associated_data=MAGIC)

    payload = MAGIC + eph_public_raw + nonce + ciphertext
    out_text = _b64e(payload) + "\n"
    _write_text(output_file, out_text)


def decrypt_file(input_file: str, output_file: str, private_key_file: str) -> None:
    recipient_private = load_private_key(private_key_file)

    payload = _b64d(_read_text(input_file).strip())

    min_len = len(MAGIC) + 32 + NONCE_SIZE + 16
    if len(payload) < min_len:
        raise ValueError("Invalid ciphertext format: insufficient length")

    if not payload.startswith(MAGIC):
        raise ValueError("Invalid ciphertext format: magic mismatch")

    cursor = len(MAGIC)
    eph_public_raw = payload[cursor : cursor + 32]
    cursor += 32
    nonce = payload[cursor : cursor + NONCE_SIZE]
    cursor += NONCE_SIZE
    ciphertext = payload[cursor:]

    eph_public = x25519.X25519PublicKey.from_public_bytes(eph_public_raw)
    shared_secret = recipient_private.exchange(eph_public)
    key = _derive_key(shared_secret)

    aead = ChaCha20Poly1305(key)
    plaintext = aead.decrypt(nonce, ciphertext, associated_data=MAGIC)

    Path(output_file).write_bytes(plaintext)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Markdown public-key encryption tool (X25519 + ChaCha20-Poly1305)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("genkey", help="Generate public/private key pair")
    p_gen.add_argument("--public", default="public_key.txt", help="Public key file path")
    p_gen.add_argument("--private", default="private_key.txt", help="Private key file path")

    p_enc = sub.add_parser("encrypt", help="Encrypt file")
    p_enc.add_argument("--in", dest="infile", default="plain.md", help="Input plaintext file")
    p_enc.add_argument("--out", dest="outfile", default="cipher.md", help="Output ciphertext file")
    p_enc.add_argument("--public", default="public_key.txt", help="Public key file path")

    p_dec = sub.add_parser("decrypt", help="Decrypt file")
    p_dec.add_argument("--in", dest="infile", default="cipher.md", help="Input ciphertext file")
    p_dec.add_argument("--out", dest="outfile", default="plain.md", help="Output plaintext file")
    p_dec.add_argument("--private", default="private_key.txt", help="Private key file path")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.cmd == "genkey":
            generate_keys(args.public, args.private)
            print(f"✅ Public key generated: {args.public}")
            print(f"✅ Private key generated: {args.private}")
        elif args.cmd == "encrypt":
            encrypt_file(args.infile, args.outfile, args.public)
            print(f"✅ Encryption complete: {args.infile} -> {args.outfile}")
        elif args.cmd == "decrypt":
            decrypt_file(args.infile, args.outfile, args.private)
            print(f"✅ Decryption complete: {args.infile} -> {args.outfile}")
        else:
            parser.error("Unknown command")
    except Exception as exc:
        print(f"❌ Failed: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
