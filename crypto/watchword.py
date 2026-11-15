# Third-party solver from the CSCTF 2026 archive (authorship unknown); flags redacted here if present.
import json, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

d = json.load(open(sys.argv[1]))
R = 0xE1 << 120
def gmul(x, y):  # GCM bit-reflected GF(2^128) multiply
    z = 0
    for i in range(127, -1, -1):
        if (y >> i) & 1: z ^= x
        x = (x >> 1) ^ R if x & 1 else x >> 1
    return z
def gpow(x, e):
    r = 1 << 127
    while e:
        if e & 1: r = gmul(r, x)
        x = gmul(x, x); e >>= 1
    return r
ginv = lambda x: gpow(x, (1 << 128) - 2)
b2i = lambda b: int.from_bytes(b, 'big')

eqs = []
for it in d['intercepts']:
    c = bytes.fromhex(it['ciphertext_hex'])
    C = b2i(c.ljust(16, b'\0'))
    L = len(c) * 8                      # len(A)=0 || len(C) bits
    T = b2i(bytes.fromhex(it['tag_hex']))
    eqs.append((C, L, T))               # T = C*H^2 + L*H + M

# differences: a H^2 + b H + c = 0
(C1, L1, T1) = eqs[0]
q = [(C1 ^ C, L1 ^ L, T1 ^ T) for C, L, T in eqs[1:]]
(a1, b1, c1), (a2, b2, c2) = q
# eliminate H^2 -> linear in H
lin = gmul(a1, b2) ^ gmul(a2, b1)
con = gmul(a1, c2) ^ gmul(a2, c1)
H = gmul(con, ginv(lin))
for a, b, c in q:
    assert gmul(a, gmul(H, H)) ^ gmul(b, H) ^ c == 0
M = T1 ^ gmul(C1, gmul(H, H)) ^ gmul(L1, H)
for C, L, T in eqs:
    assert gmul(C, gmul(H, H)) ^ gmul(L, H) ^ M == T
print("H  =", hex(H)); print("EJ0=", M.to_bytes(16, 'big').hex())
key = M.to_bytes(16, 'big')
ct = bytes.fromhex(d['sealed_master_order_ctr_hex'])
pt = Cipher(algorithms.AES(key), modes.CTR(bytes(16))).decryptor().update(ct)
print(pt)
