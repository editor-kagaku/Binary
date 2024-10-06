# snip-chop.py: データの切り出しを行うスクリプト

from refinery.units.meta import chop
from refinery.units.strings import snip

# 0(0x30)から9(0x39)、A(0x41)からF(0x46)までの16バイトのバイト列
# 0123456789ABCDEF
data = b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"

# バイト列を文字列として出力
print(f"Original data:\n{data.decode()}\n")

# 5バイト目(4)から12バイト目(B)まで、最後のバイト(F)から逆順(-1)で最後から
# 4バイト目(C)までの2つの範囲を指定してsnipクラスのインスタンスを初期化する
sn = snip.snip([slice(4, 12), slice(None, -5, -1)])

# データを切り出すジェネレータを生成する
gen = sn.process(data)

# genは要素を1つずつ返すジェネレータになるためforループで処理する
print("Snipped data:")
for snipped in gen:
    print(snipped)

print()

# 4バイトずつ分割するようにchopクラスのインスタンスを初期化する
ch = chop.chop(4)

gen = ch.process(data)

print("Chopped data:")
for chopped in gen:
    print(chopped)
