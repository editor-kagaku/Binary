# xor-rotl.py: XORとビットローテートを組み合わせてエンコードとデコードを行うスクリプト

import argparse
import sys
from refinery.lib.argformats import multibin
from refinery.units.blockwise import rotl, rotr, xor

# オプションの処理
parser = argparse.ArgumentParser()
parser.add_argument("-R", dest="opt_encode", help="エンコードを実行", action="store_true")
parser.add_argument("-r", dest="rot_bits", help="左にローテートするビット数(デコード時は右)",
                    type=int, default=0)
parser.add_argument("-x", dest="xor_key", help="XORキー(例:1234ABCD)", default="00")
args = parser.parse_args()

# 16進数で指定されたXORキーをバイナリデータに変換する
xor_key = multibin("h:" + args.xor_key)

# 標準入力からデータを受け取る
data = sys.stdin.buffer.read()

if args.opt_encode:
    # XORを実行する
    operator = xor.xor(xor_key)
    output = operator.process(data)

    # 左ビットローテートを実行する
    operator = rotl.rotl(args.rot_bits)
    output = operator.process(output)
else:
    # 右ビットローテートを実行する
    operator = rotr.rotr(args.rot_bits)
    output = operator.process(data)

    # XORを実行する
    operator = xor.xor(xor_key)
    output = operator.process(output)

# デコードしたデータを出力する。
# outputはBinary RefineryのChunkと呼ばれるクラスのインスタンスで、
# bytesであらかじめバイト列に変換してから出力する。
sys.stdout.buffer.write(bytes(output))
