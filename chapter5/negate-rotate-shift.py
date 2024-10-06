# negate-rotate-shift.py: ビット反転、ローテート、シフトを行うスクリプト

from refinery.units.blockwise import neg, rotl, rotr, shl, shr, pack

# packクラスを使ってバイト列を2進数の文字列で出力する関数
def bindump(data: bytes):
    decoder = pack.pack(base=2, width=8)
    output_gen = decoder.reverse(data)

    for output in output_gen:
        print(f"{output}\n")

# 2進数の数値からバイト列に変換
data = 0b11001001
data_bytes = data.to_bytes(length=1, byteorder="big")

print("Original data:")
bindump(data_bytes)

# ビット反転
operator = neg.neg()
output_bytes = operator.process(data_bytes)

print("neg:")
bindump(output_bytes)

operator = rotl.rotl(3)
output_bytes = operator.process(data_bytes)

# 左に3ビットローテート
print("rotl 3:")
bindump(output_bytes)

operator = rotr.rotr(4)
output_bytes = operator.process(data_bytes)

# 右に4ビットローテート
print("rotr 4:")
bindump(output_bytes)

operator = shl.shl(3)
output_bytes = operator.process(data_bytes)

# 左に3ビットシフト
print("shl 3:")
bindump(output_bytes)

# 右に4ビットシフト
operator = shr.shr(4)
output_bytes = operator.process(data_bytes)

print("shr 4:")
bindump(output_bytes)

