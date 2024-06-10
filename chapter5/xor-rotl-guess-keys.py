# xor-rotl-guess-keys.py:
# xor-rotl.pyでエンコードされたデータのローテートされたビット数とXORキーを
# 推定するスクリプト

import binascii
import sys
from refinery.lib.meta import metavars
from refinery.units.blockwise import rotr, xor
from refinery.units.misc import xkey

# 標準入力からデータを受け取る
data = sys.stdin.buffer.read()

# ローテートするビット数を変えながら右にローテートしてXORキーの推定を繰り返す
for i in range(8):
    if i == 0:
        rotr_output = data
    else:
        r = rotr.rotr(i)
        rotr_output = r.process(data)

    # XORキーの推定
    xk = xkey.xkey()
    xor_key = xk.process(rotr_output)

    # 推定したXORキーはバイナリデータになるのでbinascii.b2a_hexで
    # 16進数に変換する。この16進数の型はbytesになるため、この後に
    # printで出力する際に b'****' とならないようにdecodeしたうえで
    # さらにupperで小文字を大文字にする。
    xor_key_hex = binascii.b2a_hex(xor_key).decode().upper()

    # 推定したXORキーでデコードする
    x = xor.xor(xor_key)
    xor_output = x.process(rotr_output)

    # デコード結果のファイルの種類をmetavarsを使って判別する
    magic = metavars(xor_output).magic

    print(f"ROTL bits: {i}")
    print(f"XOR key(hex): {xor_key_hex}")
    print(f"File type: {magic}\n")
