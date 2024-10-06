
# $ python prob7-4.py PYC_1s=dec0mpilable
# Success!

import sys, itertools

def mul(matrix, vector):
    result = []

    for i in range(len(vector)):
        result.append(sum([x * y for x, y in zip(matrix[i], vector)]))

    return result

def auth(input_password, myhash, key):
    input_password += "\x00" * (7 - (len(input_password) - 1) % 8)
    p = [ord(c) for c in input_password]
    h = [mul(key, p[i : i + 8]) for i in range(0, len(p), 8)]
    h = tuple(itertools.chain.from_iterable(h))
    
    return h == myhash

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Input password.")
        exit(0)

    input_password = sys.argv[1]
    myhash = (-2365, 103, -305, -944, 1327, 1208, 259, -479, -1404, 318, -356, -978, 1384, 1945, 1509, 316, -1164, -126, -26, -350, 1129, 976, -721, -592)

    key = [
        [-9, 3, -6, -7, 9, -9, 9, -8],
        [6, -1, -6, -4, -1, 4, 3, -1],
        [-3, -5, 8, 6, -1, -4, 3, -4],
        [-3, -8, 8, -3, 6, -1, -2, -3],
        [1, 3, 7, 10, -3, -5, 3, 1],
        [9, -1, 2, 2, 6, 1, 4, -4],
        [-8, 9, -9, 3, 9, -9, 10, 4],
        [8, -9, -4, 2, 5, -6, 5, -1],
    ]

    if auth(input_password, myhash, key):
        print("Success!")
    else:
        print("Authentication failed.")
