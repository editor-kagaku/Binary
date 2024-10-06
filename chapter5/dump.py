# dump.py: ファイルへの出力を行うスクリプト

from refinery.lib.argformats import multibin
from refinery.lib.meta import metavars
from refinery.units.sinks.dump import dump

# 16進数でエンコードされた"Binary Refinery[改行]"の文字列
encoded = "h:42696E61727920526566696E6572790A"

# 文字列をデコード
decoded = multibin(encoded)

# デコード後のデータからMD5ハッシュ値とファイル拡張子を得る
md5 = metavars(decoded).md5
ext = metavars(decoded).ext

filename = f"{md5}.{ext}"

# dumpクラスのインスタンスの初期化
d = dump(filename)

# ファイルへ出力するためのジェネレータを生成
gen = d.process(decoded)

# genは要素を1つずつ返すジェネレータになるためforループで処理します。
# genから要素を読み出す際にdumpクラス内の処理によってファイルへの
# 出力が自動的に行われるため、ループ内では何もする必要はありません。
for _ in gen:
    pass

print(f"Output file: {filename}")
