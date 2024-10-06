# custom-base64.py: 通常とは異なる文字セットでBase64エンコード/デコードするスクリプト

import argparse
import sys
from refinery.units.encoding.b64 import b64

# 通常の文字セット
standard_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

# 文字をシャッフルしたカスタム文字セット
custom_charset = "ts7kKbfeTcixX1p2ZguzoqrORGNYM=w49BmWLhEJyDaA3dvC+U/H8F0n5IVQPjlS6"

# オプションの処理
parser = argparse.ArgumentParser()
parser.add_argument("-R", dest="opt_encode", help="エンコードを実行", action="store_true")
args = parser.parse_args()

# 標準入力からデータを受け取る
data_bytes = sys.stdin.buffer.read()

# b64クラスのインスタンスの初期化を行う。このスクリプトではBase64URLは使用しない。
decoder = b64(urlsafe=False)

# エンコードはreverse、デコードはprocessを実行する。
# str.maketransとtranslateを使って A <-> t, B <-> s, C <-> 7のように
# 通常の文字セットとカスタム文字セットの間で文字の置換を行う。
if args.opt_encode:
    output_bytes = decoder.reverse(data_bytes)
    output_str = output_bytes.decode()
    trans = str.maketrans(standard_charset, custom_charset)
    print(output_str.translate(trans))
else:
    trans = str.maketrans(custom_charset, standard_charset)
    data_str = data_bytes.decode()
    data_str = data_str.translate(trans)
    data_bytes = data_str.encode()
    output = decoder.process(data_bytes)
    sys.stdout.buffer.write(output)
