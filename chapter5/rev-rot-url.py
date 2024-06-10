# rev-rot-url.py: rev、rot、urlを組み合わせてデコードを行うスクリプト

from refinery.units.crypto.cipher import rot
from refinery.units.blockwise import rev
from refinery.units.encoding import url

# エンコードされた秘密の文字列
# processで直接扱えるようにここではbを付けてバイト列にしている
secret = b"79%88%5R%79%QN%5R%78%69%6R%RN%18%3R%68%SN%5R%89%7N%7R%S9%18%3R%3N%18%3R%SO%QO%4R%29%28%3R%yeh8N%18%3R%gbe8N%18%3R%ire"
print("Encoded secret: " + secret.decode())

# バイト列を逆順にする
decoder = rev.rev()
output = decoder.process(secret)
print("After rev: " + output.decode())

# ROT13のデコードを行う
decoder = rot.rot()
output = decoder.process(output)
print("After rot: " + output.decode())

# URLデコードを行う
decoder = url.url()
output = decoder.process(output)
print("After url: " + output.decode())
