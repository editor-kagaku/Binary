# peek.py: ファイルの内容の16進ダンプを出力するスクリプト
#
# --stdoutオプションを付けない場合は標準エラー出力にカラーで出力されます。出力をlessなど
# のページャを使って見たい場合は
#
# python3 peek.py filepath 2>&1 | less -r
#
# のように"2>&1"で標準エラー出力を標準出力にリダイレクトするとよいでしょう。
# lessの-rオプションはカラー出力を有効にするオプションです。

import argparse
import sys
from refinery.units.sinks import peek

# オプションや引数の処理
parser = argparse.ArgumentParser()
parser.add_argument("filepath", help="読み込むファイルのパス")
parser.add_argument("--stdout",
                    help="標準出力に出力する(デフォルトは標準エラー出力)",
                    action="store_true")
args = parser.parse_args()

try:
    # 引数で指定されたファイルを読み込む
    with open(args.filepath, "rb") as f:
        data = f.read()
except Exception as e:
    # ファイルを読み込めなかった場合はエラーメッセージを出力して終了する
    print(e)
    sys.exit(1)

# peekクラスのインスタンスの初期化
#
# all: Trueの場合はファイル全体の16進ダンプを出力します。
#      Falseの場合は10行分だけ出力します。
# gray: Trueの場合は出力に色を付けません。Falseの場合はNULLバイトがグレー、
#       英数字が白、空白文字が青、それ以外のバイトが赤で出力されます。
# stdout: Trueの場合は出力先が標準出力になります。
#         Falseの場合は標準エラー出力になります。
# expand: Trueの場合は同じ値が連続して続く際に出力を省略しないようにします。
#         Falseの場合は省略します。
# meta: Trueの場合はファイルのエントロピー、ファイルの種類、ファイルサイズ
#       の情報を複数行で表示します。Falseの場合は1行で簡略表示します。
# width: 1行に表示するバイト数
p = peek.peek(all=False, gray=False, stdout=args.stdout,
              expand=True, meta=True, width=16)

# ファイルのデータから16進ダンプ出力を生成する
output_gen = p.process(data)

# output_genは要素を1つずつ返すジェネレータになるためforループで処理します。
# 出力先がpeekクラスのデフォルトの出力先である標準エラー出力の場合は、
# output_genから要素を読み出す際に16進ダンプがpeekクラス内の処理に
# よって自動的に出力されるためループ内では何もする必要はありません。
if args.stdout:
    # 標準出力の場合はループ内で出力の処理が必要
    for output in output_gen:
        print(output)
else:
    # 標準エラー出力の場合は何もしなくてよい
    for output in output_gen:
        pass
