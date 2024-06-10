# multibin.py: multibin()関数を使ってデコードするスクリプト

import base64
import binascii
import urllib.parse
import refinery.lib.argformats
import sys

# エンコードされた文字列のリスト
encoded_list = ["h:507974686F6EE381A7",
                "q:%E5%AE%9F%E8%B7%B5%E3%81%99%E3%82%8B",
                "b64:44OQ44Kk44OK44Oq6Kej5p6Q"]

# print()とsys.stdout.buffer.write()が混在していると、
# print()はバッファリングがあり、sys.stdout.buffer.write()は
# バッファリングがないことで出力の順序が変わってしまうため、
# このスクリプトでは全てsys.stdout.buffer.write()に統一する。
# メッセージはencode()でUTF-8のバイト列に変換しておく。
message = "Binary Refineryでのデコード結果:\n".encode()
sys.stdout.buffer.write(message)
for encoded in encoded_list:
    # 文字列をデコード
    decoded = refinery.lib.argformats.multibin(encoded)

    # デコードした文字列をバイト列として出力
    sys.stdout.buffer.write(decoded)

    # デコードした文字列には改行が含まれていないため改行を出力
    sys.stdout.buffer.write(b"\n")

message = "\nPython標準ライブラリでのデコード結果:\n".encode()
sys.stdout.buffer.write(message)
for encoded in encoded_list:
    # 標準のPythonモジュールの場合はエンコーディングの種別を表す部分を
    # 取り除いてからデコードする
    if encoded[:2] == "h:":
        # 16進数の文字列をデコード
        decoded = binascii.a2b_hex(encoded[2:])
        sys.stdout.buffer.write(decoded)
    elif encoded[:2] == "q:":
        # URLエンコードされた文字列をバイト列にデコード
        decoded = urllib.parse.unquote_to_bytes(encoded[2:])

        sys.stdout.buffer.write(decoded)
    elif encoded[:4] == "b64:":
        # Base64エンコードされた文字列をデコード
        decoded = base64.b64decode(encoded[4:])
        sys.stdout.buffer.write(decoded)

    sys.stdout.buffer.write(b"\n")
