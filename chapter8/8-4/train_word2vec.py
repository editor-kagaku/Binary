import os
import sys
import r2pipe
import glob
import pandas as pd
import re
from gensim.models import Word2Vec

def analyze_binary(path):
    """
    バイナリファイルを解析し、関数リストとr2オブジェクトを返す

    Args:
        path (str): バイナリファイルのパス

    Returns:
        tuple: 関数リストとr2オブジェクト
    """
    r2 = r2pipe.open(path, flags=["-2"])
    r2.cmd("aaa")
    afl = r2.cmdj("aflj")
    return afl, r2

def get_functions(afl):
    """
    関数リストから各関数のオフセットを取得する

    Args:
        afl (list): 関数リスト

    Returns:
        list: 各関数のオフセット
    """
    offsets = set()
    for f in afl:
        offsets.add(f.get("offset", None))
    return list(offsets)

def get_assembly_instructions(r2, offset):
    """
    指定されたオフセットのアセンブリ命令を取得する

    Args:
        r2 (r2pipe.open): r2オブジェクト
        offset (int): 関数のオフセット

    Returns:
        list: アセンブリ命令のリスト
    """
    pdf = r2.cmdj(f'pdfj @{offset}')
    instructions = []
    for d in pdf.get('ops', []):
        if d.get("disasm"):
            instructions.append(d.get("disasm"))
    return instructions

def normalize_instruction(instruction):
    """
    アセンブリ命令を正規化する

    Args:
        instruction (str): アセンブリ命令

    Returns:
        str: 正規化されたアセンブリ命令
    """
    parts = instruction.split(maxsplit=1)
    opcode = parts[0]
    operands = parts[1] if len(parts) > 1 else ''
    normalized_operands = re.sub(r'\b0x[a-fA-F0-9]+\b', 'N', operands)
    normalized_operands = re.sub(r'\s*,\s*', '_', normalized_operands)
    normalized_operands = re.sub(r'\s+', '', normalized_operands)
    normalized = opcode
    if normalized_operands:
        normalized += '_' + normalized_operands
    return normalized

def train_word2vec(input_dir, output_model):
    """
    Word2Vecモデルをトレーニングして保存する

    Args:
        input_dir (str): 入力ディレクトリのパス
        output_model (str): 出力モデルファイルのパス
    """
    data_list = []

    # 実行ファイルのパスを取得
    files = glob.glob(os.path.join(input_dir, '*'))

    # 各ファイルに対して処理を実行
    for file in files:
        print(f'Processing file: {file}')
        afl, r2 = analyze_binary(file)
        offsets = get_functions(afl)
        for offset in offsets:
            asm = get_assembly_instructions(r2, offset)
            if asm:
                normalized_asm_list = [normalize_instruction(instr) for instr in asm]
                data_list.append(normalized_asm_list)
        print(f'Finished processing file: {file}')

    print('Training Word2Vec model...')
    model = Word2Vec(data_list, vector_size=100, window=2, min_count=1, workers=4)
    print('Training complete.')
    model.save(output_model)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python train_word2vec.py <input_dir> <output_model>")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_model = sys.argv[2]

    train_word2vec(input_dir, output_model)
