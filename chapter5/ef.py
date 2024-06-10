# ef.py: ファイルの情報と先頭部分の内容を出力するスクリプト

import argparse
import refinery.units.meta.ef

def show_text_content(content: str):
    # 先頭から32文字までを表示する
    if len(content) > 32:
        content = content[:32]
        print(f"Content:{content}...")
    else:
        print(f"Content:{content}")

def show_binary_content(content: bytes):
    # バイナリデータをそのまま出力すると文字化けしてしまうため
    # 16進数に変換する
    content_hex = content.hex()

    # 先頭から32文字まで(ファイルの先頭から16バイト分)を表示する
    if len(content_hex) > 32:
        content_hex = content_hex[:32]
        print(f"Content(hex):{content_hex}...")
    else:
        print(f"Content(hex):{content_hex}")

# オプションや引数の処理
parser = argparse.ArgumentParser()
parser.add_argument("filepath", help="読み込むファイルのパス")
args = parser.parse_args()

# efクラスのインスタンスの初期化
ef = refinery.units.meta.ef.ef(args.filepath)

# ファイルのデータを読み出すジェネレータを生成する
data_gen = ef.process(None)

# data_genはジェネレータであるためループで処理する必要がある
for data in data_gen:
    # cfmtコマンドでも使用可能なメタデータを取得して表示する
    path = data.meta.get("path")
    size = data.meta.get("size")
    ext = data.meta.get("ext")
    magic = data.meta.get("magic")

    print(f"Path:{path}")
    print(f"Size:{size}")
    print(f"Extension:{ext}")
    print(f"Type:{magic}")

    # ファイルの種類がテキストの場合はそのまま表示する
    if b"text" in magic:
        # dataはBinary RefineryのChunkと呼ばれるクラスのインスタンスで、
        # これをUTF-8のテキストとしてデコードしてstrの文字列に変換する
        content = data.decode()
        show_text_content(content)
    else:
        # dataをバイト列として処理したい場合はbytes()でバイト列に変換する
        content = bytes(data)
        show_binary_content(content)
