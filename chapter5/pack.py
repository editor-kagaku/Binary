# pack.py: 2進数、8進数、10進数、16進数のデコードとエンコードを行うスクリプト

import argparse
import sys
import types
from refinery.units.blockwise import pack

# オプションの処理
# -2、-8、-10、-16のいずれかの指定を必須にする
parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-2", dest="opt_bin", help="2進数のデコード", action="store_true")
group.add_argument("-8", dest="opt_oct", help="8進数のデコード", action="store_true")
group.add_argument("-10", dest="opt_dec", help="10進数のデコード", action="store_true")
group.add_argument("-16", dest="opt_hex", help="16進数のデコード", action="store_true")
parser.add_argument("-R", dest="opt_encode", help="エンコードを実行", action="store_true")
parser.add_argument("-s", dest="opt_separator",
                    help="エンコード時の出力の区切り文字", action="store", type=str)
args = parser.parse_args()

# 標準入力からデータを受け取る
data = sys.stdin.buffer.read()

# オプションに応じてpackクラスの初期化を行う
if args.opt_bin:
    decoder = pack.pack(base=2, width=8)
elif args.opt_oct:
    decoder = pack.pack(base=8)
elif args.opt_dec:
    decoder = pack.pack(base=10)
elif args.opt_hex:
    decoder = pack.pack(base=16, width=2)

# エンコードはreverse()、デコードはprocess()を実行する
if args.opt_encode:
    output = decoder.reverse(data)
else:
    output = decoder.process(data)

# 出力がジェネレータの場合はループで処理する
if type(output) is types.GeneratorType:
    o = next(output)
    while True:
        try:
            # エンコードしたデータを出力する
            sys.stdout.buffer.write(bytes(o))

            # 次の要素を先読みする。上で出力したデータが最後の要素で
            # もう要素が残っていない場合はStopIterationの例外が発生
            # してこの下の区切り文字を出力する処理はスキップされる。
            o = next(output)

            # decode("unicode_escape")を実行することで\nを改行に、
            # \tをタブに変換できる。
            if args.opt_separator:
                sep = args.opt_separator.encode()
                sep = sep.decode("unicode_escape").encode()
                sys.stdout.buffer.write(sep)
        except StopIteration:
            break
else:
    # デコードしたデータを出力する。
    # outputはBinary RefineryのChunkと呼ばれるクラスのインスタンスで、
    # bytes()であらかじめバイト列に変換してから出力する。
    sys.stdout.buffer.write(bytes(output))

# エンコードする場合は最後に改行を出力する
if args.opt_encode:
    sys.stdout.buffer.write(b"\x0a")
