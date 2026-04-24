# mycrypt (Python version)

Use **X25519 + ChaCha20-Poly1305** to encrypt Markdown files with a public key and decrypt with a private key.

## File Overview

- `plain.md`: plaintext input
- `cipher.md`: ciphertext output (Base64 text)
- `public_key.txt`: public key (Base64)
- `private_key.txt`: private key (Base64)
- `mycrypt.py`: main program
- `myrsa.py`: backward-compatible alias

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### 1) Generate keys (default paths)

```bash
python mycrypt.py genkey
```

### 2) Encrypt (`plain.md` -> `cipher.md`, default paths)

```bash
python mycrypt.py encrypt
```

### 3) Decrypt (`cipher.md` -> `plain.md`, default paths)

```bash
python mycrypt.py decrypt
```

You can still use the old command name if needed:

```bash
python myrsa.py genkey
python myrsa.py encrypt
python myrsa.py decrypt
```

Optional custom paths are also supported:

```bash
python mycrypt.py genkey --public public_key.txt --private private_key.txt
python mycrypt.py encrypt --in plain.md --out cipher.md --public public_key.txt
python mycrypt.py decrypt --in cipher.md --out plain.md --private private_key.txt
```

## Notes

- Never expose `private_key.txt`.
- Share `public_key.txt` with others so they can encrypt messages for you.
- If ciphertext is tampered with, decryption will fail (integrity check).
