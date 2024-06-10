# deobfuscate.py: 難読化されたPHPコードを可読化するスクリプト

import sys
import refinery.units.blockwise.rev
import refinery.units.compression.zl
import refinery.units.crypto.cipher.rot
import refinery.units.encoding.b64

# 難読化されたPHPコード
# ここではbytesとして扱うため b"" を使っている。
obfuscated = b"==NN9U624/57W8J1whjN21O27Ua78oBMpUf942XclelXOdnMzGWu0oA/tII4OZZChvKDcBmluAG4wt4wWDoyYqClnfaN5NTWVSk/+XLP0MUrp1nwxorLBH7dXc80V9QSu6iscl+DrYrNrljIWMx94eq3z8hJ49InAhQwF3v3F8nRrXk9eKFBc6jn5RPMVC9Op86NbpLXVOxntNcej2LZpwgR4fFaJX41F0QNUKqsugGM8z7nsxLTY17EHoCE37F5h+Vq41Gk3XQiXMdsiF4uRhZkYujKV8PPUTy3tDLwigp9ymeFf6svBx4W43WEEJkRuovjQ91ECI8Y9evMloMEwSFW4B5iWzEsU4RUvfSc2YpTvMWfvIfc4FCEh+XmLyZmxSfEBCegXo0Pz9BbFbOsMi9LHx7t9/s+mwWUpyhRnmp0icThz/EGXNkvFalQjdVX+BZFYWxkaSLRFAev1htyeCTrQN97WrgLPO6vBzl9isZSOWtFqQMM"

# ROT13のデコード
rot = refinery.units.crypto.cipher.rot.rot()
output = rot.process(obfuscated)

# 文字列の順序の反転
rev = refinery.units.blockwise.rev.rev()
output = rev.process(output)

# Base64のデコード
b64 = refinery.units.encoding.b64.b64()
output = b64.process(output)

# Deflateアルゴリズムでの展開(zlibヘッダ無し)
zl = refinery.units.compression.zl.zl()
output = zl.process(output)

# 可読化されたPHPコードはbytesとなっているため、
# print()の代わりにsys.stdout.buffer.write()で出力する
sys.stdout.buffer.write(output)
