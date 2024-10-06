# $ python solve7-4.py
# PYC_1s=dec0mpilable

from sympy import Matrix

myhash = Matrix((-2365, 103, -305, -944, 1327, 1208, 259, -479, -1404, 318, -356, -978, 1384, 1945, 1509, 316, -1164, -126, -26, -350, 1129, 976, -721, -592))

key = Matrix(
    [
        [-9, 3, -6, -7, 9, -9, 9, -8],
        [6, -1, -6, -4, -1, 4, 3, -1],
        [-3, -5, 8, 6, -1, -4, 3, -4],
        [-3, -8, 8, -3, 6, -1, -2, -3],
        [1, 3, 7, 10, -3, -5, 3, 1],
        [9, -1, 2, 2, 6, 1, 4, -4],
        [-8, 9, -9, 3, 9, -9, 10, 4],
        [8, -9, -4, 2, 5, -6, 5, -1],
    ]
)

invkey = key.inv()
ans = list([invkey * Matrix(myhash[i:i+8]) for i in range(0, len(myhash), 8)])
print("".join([chr(x[y]) for x in ans for y in range(8) if x[y] != 0]))
