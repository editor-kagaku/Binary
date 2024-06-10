# custom_layers.py
import torch
from torch import Tensor
from torch_geometric.nn.aggr import Aggregation
from torch_geometric.utils import softmax
from typing import Optional, Tuple

# Set2Set Aggregationクラス
class Set2Set(Aggregation):
    def __init__(self, in_channels: int, processing_steps: int, **kwargs):
        super().__init__()
        self.in_channels = in_channels
        self.out_channels = 2 * in_channels
        self.processing_steps = processing_steps
        self.lstm = torch.nn.LSTM(self.out_channels, in_channels, **kwargs)
        self.reset_parameters()

    def reset_parameters(self):
        self.lstm.reset_parameters()

    def forward(self, x: Tensor, index: Optional[Tensor] = None,
                ptr: Optional[Tensor] = None, dim_size: Optional[int] = None,
                dim: int = -2) -> Tensor:
        # インデックスが存在するかを確認
        self.assert_index_present(index)
        # 入力が二次元であることを確認
        self.assert_two_dimensional_input(x, dim)

        # LSTMの初期状態を設定
        h = (x.new_zeros((self.lstm.num_layers, dim_size, x.size(-1))),
             x.new_zeros((self.lstm.num_layers, dim_size, x.size(-1))))
        q_star = x.new_zeros(dim_size, self.out_channels)

        a_list = []

        for _ in range(self.processing_steps):
            q, h = self.lstm(q_star.unsqueeze(0), h)
            q = q.view(dim_size, self.in_channels)
            e = (x * q[index]).sum(dim=-1, keepdim=True)
            a = softmax(e, index, ptr, dim_size, dim)
            a_list.append(a)
            r = self.reduce(a * x, index, ptr, dim_size, dim, reduce='add')
            q_star = torch.cat([q, r], dim=-1)

        return q_star, a_list

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.in_channels}, {self.out_channels})'

# ドロップアウトエッジ関数
def dropout_edge(edge_index: Tensor, p: float = 0.5,
                 force_undirected: bool = False,
                 training: bool = True) -> Tuple[Tensor, Tensor]:
    if p < 0. or p > 1.:
        raise ValueError(f'Dropout probability has to be between 0 and 1 (got {p})')

    if not training or p == 0.0:
        edge_mask = edge_index.new_ones(edge_index.size(1), dtype=torch.bool)
        return edge_index, edge_mask

    row, col = edge_index
    edge_mask = torch.rand(row.size(0), device=edge_index.device) >= p

    if force_undirected:
        edge_mask[row > col] = False

    edge_index = edge_index[:, edge_mask]

    if force_undirected:
        edge_index = torch.cat([edge_index, edge_index.flip(0)], dim=1)
        edge_mask = edge_mask.nonzero().repeat((2, 1)).squeeze()

    return edge_index, edge_mask
