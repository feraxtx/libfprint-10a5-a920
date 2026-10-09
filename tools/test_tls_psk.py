import hashlib
import hmac

def tls_prf(secret, label, seed, length):
    # RFC 5246 P_hash using SHA256
    def p_hash(secret, seed, length):
        result = bytearray()
        a = seed
        while len(result) < length:
            a = hmac.new(secret, a, hashlib.sha256).digest()
            result.extend(hmac.new(secret, a + seed, hashlib.sha256).digest())
        return bytes(result[:length])
    
    return p_hash(secret, label.encode("latin1") + seed, length)

# Let's extract client_random and server_random
# ClientHello from frame 132/134:
# random starts at offset 5 + 4 + 2 = 11, length 32
# Frame 132 data:
ch_hex = "160301004701000043030348edf7ce3e27d101bdec290c0c29bf0ddfd1f2eb39567637920049eb73ecbdcd00000800a900a800ae00ff01000012000a000400020018000b0002010000170000"
ch = bytes.fromhex(ch_hex)
client_random = ch[11:43]
print("Client random:", client_random.hex())

# ServerHello from frame 136/138:
sh_hex = "16030300550200005103034419ed72189fd1aeee597ce0d1b9a684de9aa8f1c08ce24924f353c5a0a5d5de20c90907b390edbacc686b42625f9d0017675a7085f1920094ddd3de76bedd574200a8000009ff0100010000170000"
sh = bytes.fromhex(sh_hex)
server_random = sh[11:43]
print("Server random:", server_random.hex())

# Let's check candidate PSKs
# 1) If key was decrypted with FPC_SEALING_KEY
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key_hex = "bdda29fcc06448d1ca5ae7e1277b65c69676aae4fecafa26bacebe802bc8d68d"
enc_key = bytes.fromhex(key_hex)

candidates = []

# Try different sealing keys
for label in [b"FPC_SEALING_KEY\0", b"FPC_SEALING_KEY", b"FPC_KEY\0", b"FPC_KEY", b"Disum PSK\0", b"Disum PSK"]:
    sk = hashlib.sha256(label).digest()
    for iv in [b"\x00"*16, enc_key[:16]]:
        try:
            cipher = Cipher(algorithms.AES(sk), modes.CBC(b"\x00"*16))
            dec = cipher.decryptor()
            candidates.append((label, dec.update(enc_key) + dec.finalize()))
        except:
            pass

# Also candidate: raw enc_key itself
candidates.append((b"raw_enc_key", enc_key))

# What is Client Finished record in frame 146?
# Frame 146: 16 03 03 00 28 ...
# Length 40 = 0x28. AES-GCM tag is 16 bytes, explicit nonce is 8 bytes, verify_data is 12 bytes = 20 + 8 + 16 = ... wait!
# In TLS 1.2 AES-128-GCM:
# Record payload: 8 bytes explicit nonce + ciphertext + 16 bytes auth tag.
# For Finished handshake message:
# Handshake msg = 4 bytes header (14 00 00 0c) + 12 bytes verify_data = 16 bytes plaintext!
# 16 bytes plaintext + 8 bytes nonce + 16 bytes tag = 40 bytes (0x28)! EXACT MATCH!
f146 = bytes.fromhex("160303002800000000000000008fb62bf17e91e78deab60f36f9b4dd3ac1e5e6b02008ee7328bf589d8199723ecdbf7a5c")
nonce_explicit = f146[5:13] # 00 00 00 00 00 00 00 00
ciphertext = f146[13:13+16]
tag = f146[13+16:]
print("Nonce explicit:", nonce_explicit.hex())
print("Ciphertext:", ciphertext.hex())
print("Tag:", tag.hex())

# Let's compute handshake transcript hash up to Client Finished:
# Messages in order:
# 1. ClientHello (without 5-byte record header: ch[5:])
# 2. ServerHello (sh[5:])
# 3. ServerHelloDone (from frame 140: 0e 00 00 00)
# 4. ClientKeyExchange (from frame 142: 10 00 00 0b 00 09 44 69 73 75 6d 20 50 53 4b)
shd = bytes.fromhex("0e000000")
cke = bytes.fromhex("1000000b0009446973756d2050534b")
handshake_msgs = ch[5:] + sh[5:] + shd + cke
transcript_hash = hashlib.sha256(handshake_msgs).digest()
print("Transcript hash:", transcript_hash.hex())

for name, psk in candidates:
    # PSK pre-master secret for pure PSK:
    # RFC 4279:
    # uint16 len, len zeros, uint16 len, psk
    pms = len(psk).to_bytes(2, "big") + b"\x00"*len(psk) + len(psk).to_bytes(2, "big") + psk
    ms = tls_prf(pms, "master secret", client_random + server_random, 48)
    
    # Key expansion for AES-128-GCM:
    # 2 * 0 bytes (no MAC key for AEAD)
    # 2 * 16 bytes write key
    # 2 * 4 bytes write IV (fixed IV)
    # Total = 32 + 8 = 40 bytes
    key_block = tls_prf(ms, "key expansion", server_random + client_random, 40)
    client_write_key = key_block[0:16]
    server_write_key = key_block[16:32]
    client_write_iv = key_block[32:36]
    server_write_iv = key_block[36:40]
    
    # Compute verify_data:
    verify_data = tls_prf(ms, "client finished", transcript_hash, 12)
    expected_handshake = b"\x14\x00\x00\x0c" + verify_data
    
    # Try to decrypt with AES-GCM
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(client_write_key)
    nonce = client_write_iv + nonce_explicit
    # Additional authenticated data for TLS 1.2:
    # 8-byte seq_num (0 for first message after CCS) + record header (16 03 03 00 10)
    # Note: length in AAD is plaintext length (16 bytes = 0x0010)
    aad = b"\x00"*8 + b"\x16\x03\x03\x00\x10"
    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext + tag, aad)
        print(f"SUCCESS with {name}! Decrypted: {decrypted.hex()}")
        print(f"Expected:           {expected_handshake.hex()}")
        print(f"Match: {decrypted == expected_handshake}")
        print(f"PSK was: {psk.hex()}")
        break
    except Exception as e:
        pass
