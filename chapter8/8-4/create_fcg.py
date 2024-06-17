import os
import sys
import pandas as pd
import torch
import networkx as nx
from torch_geometric.data import Data
from torch_geometric.utils import from_networkx
import r2pipe
from gensim.models import Word2Vec
import pickle
import re

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

def create_fcg(input_dir, output_pkl, word2vec_model_path):
    """
    FCGを作成してデータセットを保存する

    Args:
        input_dir (str): 入力ディレクトリのパス
        output_pkl (str): 出力pklファイルのパス
        word2vec_model_path (str): Word2Vecモデルのパス
    """
    data_list = []
    model = Word2Vec.load(word2vec_model_path)

    def vectorize_assembly_instruction(instruction):
        """
        アセンブリ命令をベクトル化する

        Args:
            instruction (str): アセンブリ命令

        Returns:
            list: ベクトル化されたアセンブリ命令
        """
        if instruction in model.wv:
            return model.wv[instruction]
        else:
            print(f'Instruction {instruction} not found in vocabulary')
            return [0] * model.vector_size

    total_files = 0
    for subdir, _, files in os.walk(input_dir):
        if subdir == input_dir:
            continue  # ルートディレクトリはスキップ

        label = int(os.path.basename(subdir))
        for file in files:
            filepath = os.path.join(subdir, file)

            # バイナリファイルを開いて解析
            r2 = r2pipe.open(filepath)
            r2.cmd('aaa')
            r2.cmd('agCd > graph.dot')

            # DOTファイルをNetworkXグラフに変換
            G = nx.DiGraph(nx.drawing.nx_pydot.read_dot('graph.dot'))
            node_attrs = []
            func_names = []
            for node in G.nodes:
                # 各ノードのアセンブリ命令を取得
                asm = get_assembly_instructions(r2, node)
                func_names.append(node)
                if asm:
                    # アセンブリ命令を正規化してベクトル化
                    normalized_asm = [normalize_instruction(instr) for instr in asm]
                    vectorized_asm = [vectorize_assembly_instruction(instr) for instr in normalized_asm]
                    node_attrs.append(torch.tensor(vectorized_asm, dtype=torch.float).mean(dim=0).tolist())
                else:
                    node_attrs.append([0] * model.vector_size)

            # エッジリストを作成
            edge_index = []
            for edge in G.edges:
                edge_index.append([list(G.nodes).index(edge[0]), list(G.nodes).index(edge[1])])

            # 必要な属性だけをPyGデータに変換
            data = Data(
                x=torch.tensor(node_attrs, dtype=torch.float),
                edge_index=torch.tensor(edge_index, dtype=torch.long).t().contiguous(),
                y=torch.tensor([label]),
                num_nodes=len(node_attrs),
                funcname=func_names  # 文字列のリストとして保存
            )
            data_list.append(data)
            total_files += 1

            print(f"Processed file {file} with label {label}")

    # データセットをpklファイルとして保存
    with open(output_pkl, 'wb') as f:
        pickle.dump(data_list, f)

    print(f"FCG creation completed, processed {total_files} files")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python create_fcg.py <input_dir> <output_pkl> <word2vec_model_path>")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_pkl = sys.argv[2]
    word2vec_model_path = sys.argv[3]

    create_fcg(input_dir, output_pkl, word2vec_model_path)
