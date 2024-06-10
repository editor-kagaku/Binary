# xor-rotl.py: XORとビットローテートを組み合わせてエンコードとデコードを行うスクリプト

import argparse
import sys
from refinery.lib.argformats import multibin
from refinery.units.blockwise import rotl, rotr, xor

# オプションの処理
parser = argparse.ArgumentParser()
parser.add_argument("-R", dest="opt_encode", help="エンコードを実行", action="store_true")
parser.add_argument("-r", dest="rot_bits", help="左にローテートするビット数(デコード時は右)",
                    action="store", type=int, default=0)
parser.add_argument("-x", dest="xor_key", help="XORキー(例:1234ABCD)", action="store",
                    default="00")
args = parser.parse_args()

# 16進数で指定されたXORキーをバイナリデータに変換する
xor_key = multibin("h:" + args.xor_key)

# 8ビット分ローテートすると一周して元の値に戻るため、ローテートするビット数が
# 8以上の場合はビット数を8の剰余にして演算回数を減らす
rot_bits = args.rot_bits % 8

# 標準入力からデータを受け取る
data = sys.stdin.buffer.read()

if args.opt_encode:
    # XORを実行する
    operator = xor.xor(xor_key)
    output = operator.process(data)

    # 左ビットローテートを実行する
    operator = rotl.rotl(rot_bits)
    output = operator.process(output)
else:
    # 右ビットローテートを実行する
    operator = rotr.rotr(rot_bits)
    output = operator.process(data)

    # XORを実行する
    operator = xor.xor(xor_key)
    output = operator.process(output)

# デコードしたデータを出力する。
# outputはBinary RefineryのChunkと呼ばれるクラスのインスタンスで、
# bytesであらかじめバイト列に変換してから出力する。
sys.stdout.buffer.write(bytes(output))
