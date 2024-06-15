import os, sys, struct, string
import itertools

def rand(s):
    a = 1103515245
    b = 12345
    c = 2147483647
    x = s

    while True:
        x = (a * x + b) & c
        yield x & 0xFFFF

def enc(msg):
    key = rand(struct.unpack("<H", msg[0:2])[0])
    encoded_msg = []

    for i in range(2, len(msg), 2):
        e = struct.unpack("<H", msg[i:i+2])[0]
        r = next(key)
        encoded_msg.append(struct.pack("<H", e ^ r))

    encoded_bytes = b"".join(encoded_msg)
    return encoded_bytes

def solve(encoded_msg):
    for initial_msg in itertools.product(range(0x20, 0x7F), repeat=2):
        key = rand(struct.unpack("<H", struct.pack("<2B", *initial_msg))[0])
        msg = [struct.pack("<2B", *initial_msg)]

        for i in range(0, len(encoded_msg), 2):
            e = struct.unpack("<H", encoded_msg[i:i+2])[0]
            r = next(key)
            msg.append(struct.pack("<H", e ^ r))

        decoded_msg = b"".join(msg)
        if all(chr(c) in string.printable for c in decoded_msg):
            return decoded_msg

    return False

#print(enc(b"Reversing1sFun"))
#print(solve(enc(b"Reversing1sFun")))
print(solve(b"\x55\x35\x52\x8a\xb0\x6c\xf9\xb5\x0c\x8d\x39\xe9"))

