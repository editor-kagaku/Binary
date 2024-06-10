# add-sub.py: 加算と減算を行うスクリプト

from refinery.units.blockwise import add, sub
from refinery.units.sinks import peek

# peekクラスを使ってデータの16進ダンプを出力する関数
def hexdump(data: bytes):
    # bare=Trueの場合はサイズ、ファイルの種類、エントロピーの情報を表示しない
    p = peek.peek(width=16, bare=True, stdout=True)
    output_gen = p.process(data)

    for output in output_gen:
        print(output)

    print("--------------------------------------------------------------------\n")

data = b"\x00\x11\x22\x33\x44\x55\x66\x77"

print("Original data:")
hexdump(data)

operator = add.add(8)
output = operator.process(data)

print("add 8:")
hexdump(output)

operator = sub.sub(8)
output = operator.process(data)

print("sub 8:")
hexdump(output)

operator = add.add(b"\x11\x22\x33\x44")
output = operator.process(data)

print("add h:11223344:")
hexdump(output)

operator = add.add(0x44332211)
output = operator.process(data)

print("add 0x44332211:")
hexdump(output)

operator = sub.sub(b"\x11\x22\x33\x44")
output = operator.process(data)

print("sub h:11223344:")
hexdump(output)

operator = sub.sub(0x44332211)
output = operator.process(data)

print("sub 0x44332211:")
hexdump(output)
