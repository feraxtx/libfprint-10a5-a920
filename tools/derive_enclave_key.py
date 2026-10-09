with open("scratch/driver/x64/fpc_enclave.dll", "rb") as f:
    dll = f.read()

# Let's map RVA to file offset:
# .rdata: VMA 0x180082000, File off 0x80c00
def rva_to_off(rva):
    return rva - 0x82000 + 0x80c00

# Function logic:
# r11 = 0x180084510 -> RVA 0x84510
# r10 = 0x180000000, so:
# 0x85010
# 0x84ff0
# 0x83398
arr1 = dll[rva_to_off(0x84510):rva_to_off(0x84510)+64]
arr2 = dll[rva_to_off(0x85010):rva_to_off(0x85010)+64]
arr3 = dll[rva_to_off(0x84ff0):rva_to_off(0x84ff0)+64]
arr4 = dll[rva_to_off(0x83398):rva_to_off(0x83398)+64]

print("arr1 len:", len(arr1))
print("arr2 len:", len(arr2))
print("arr3 len:", len(arr3))
print("arr4 len:", len(arr4))

# Let's replicate the loop:
# r9 = 0
# ecx = 2
pwd = bytearray(32)
ecx = 2
for r9 in range(32):
    eax = (ecx - 1) & 0x1f
    r8d = (ecx + 1)
    
    # idx1:
    idx1 = eax
    # idx2:
    idx2 = r8d & 0x1f
    # dl = arr1[idx1] ^ arr2[idx2]
    dl = arr1[idx1] ^ arr2[idx2]
    
    # idx3:
    idx3 = ecx & 0x1f
    ecx = r8d
    
    # idx4:
    idx4 = r9
    
    dl = dl ^ arr3[idx3] ^ arr4[idx4]
    pwd[r9] = dl

print("Constructed password (hex):", pwd.hex())

# Now run PBKDF2:
# In C:
# cIterations = 0x4b0 = 1200
# pbSalt = NULL, cbSalt = 0 (or is pbSalt NULL?)
# pbDerivedKey: 32 bytes (or edi bytes)
# Let's test with hashlib.pbkdf2_hmac:
import hashlib
derived1 = hashlib.pbkdf2_hmac("sha256", bytes(pwd), b"", 1200, 32)
print("Derived key with empty salt (hex):", derived1.hex())
