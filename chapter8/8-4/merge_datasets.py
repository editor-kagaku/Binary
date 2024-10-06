import pickle
import argparse

def merge_datasets(dataset1_path, dataset2_path, output_path):
    """
    2つのデータセットを結合して保存する

    Args:
        dataset1_path (str): 1つ目のデータセットのパス
        dataset2_path (str): 2つ目のデータセットのパス
        output_path (str): 出力データセットのパス
    """
    # 1つ目のデータセットを読み込む
    with open(dataset1_path, 'rb') as f:
        dataset1 = pickle.load(f)

    # 2つ目のデータセットを読み込む
    with open(dataset2_path, 'rb') as f:
        dataset2 = pickle.load(f)

    # データセットを結合する
    combined_dataset = dataset1 + dataset2

    # 結合されたデータセットを保存する
    with open(output_path, 'wb') as f:
        pickle.dump(combined_dataset, f)

    print(f"Datasets merged and saved to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge two datasets and save the result.")
    parser.add_argument("dataset1_path", type=str, help="Path to the first dataset")
    parser.add_argument("dataset2_path", type=str, help="Path to the second dataset")
    parser.add_argument("output_path", type=str, help="Path to save the merged dataset")

    args = parser.parse_args()
    merge_datasets(args.dataset1_path, args.dataset2_path, args.output_path)
