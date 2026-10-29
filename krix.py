import hashlib, os, base64

def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    seed = hashlib.sha256(key + nonce).digest()
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]

def _rotl8(b: int, n: int) -> int:
    n %= 8
    return ((b << n) | (b >> (8 - n))) & 0xFF

def _rotr8(b: int, n: int) -> int:
    n %= 8
    return ((b >> n) | (b << (8 - n))) & 0xFF

def encrypt(plaintext: str, key: str) -> str:
    P = plaintext.encode("utf-8")
    K = key.encode("utf-8")
    nonce = os.urandom(16)
    KS = _keystream(K, nonce, len(P))
    X = bytearray()
    for i, p in enumerate(P):
        r = _rotl8(p, (i % 8) + 1)
        salt = (i * 31 + 17) % 256
        X.append(r ^ KS[i] ^ salt)
    C = bytearray()
    prev = nonce[0]
    for x in X:
        c = x ^ prev
        C.append(c)
        prev = c
    return base64.b64encode(nonce + bytes(C)).decode()

def decrypt(ciphertext_b64: str, key: str) -> str:
    raw = base64.b64decode(ciphertext_b64)
    nonce, C = raw[:16], raw[16:]
    K = key.encode("utf-8")
    KS = _keystream(K, nonce, len(C))
    X = bytearray()
    prev = nonce[0]
    for c in C:
        x = c ^ prev
        X.append(x)
        prev = c
    P = bytearray()
    for i, x in enumerate(X):
        salt = (i * 31 + 17) % 256
        r = x ^ KS[i] ^ salt
        P.append(_rotr8(r, (i % 8) + 1))
    return P.decode("utf-8")