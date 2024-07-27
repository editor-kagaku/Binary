# decompress.py: 圧縮ファイルを展開するスクリプト

import argparse
import os
import sys
from refinery.lib import meta
from refinery.units.compression import decompress

# オプションや引数の処理
parser = argparse.ArgumentParser()
parser.add_argument("filepath", help="圧縮ファイルのパス")
args = parser.parse_args()

# バイナリモードでファイルを読み込む
with open(args.filepath, "rb") as f:
    data = f.read()

# 圧縮ファイルの種類を判別する
magic = meta.metavars(data).magic
print(f"Type: {magic}")

# prepend=Falseはコマンドで-Pオプションを付けた場合と同様の動作となる
decomp =  decompress.decompress(prepend=False)
output = decomp.process(data)

# outputとdataが同一の場合は展開に失敗しているため、
# 標準エラー出力にエラーメッセージを表示する。
if output == data:
    print("エラー: 展開に失敗しました。", file=sys.stderr)
else:
    # textfile.txt.gzのように末尾に圧縮ファイルの拡張子が付いていると仮定して、
    # その拡張子を除いたファイル名で展開されたファイルを作成する。
    #
    # 例えばos.path.splitext()はtextfile.txt.gzをtextfile.txtとgzに分割
    # するので、textfile.txtの部分([0])を出力ファイル名として使用する。
    output_path = os.path.splitext(args.filepath)[0]

    # バイナリモードでファイルを書き込む
    with open(output_path, "wb") as f:
        f.write(output)

    print(f"{output_path}にファイルを展開しました。")
