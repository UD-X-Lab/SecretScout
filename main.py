import os

import pandas as pd
import yaml

import src.util as util
from src.ConfigScanner import ConfigScanner

# Load ground truth
secret_labels = pd.read_csv("data/evaluation/evaluation-dataset-labels.csv")
labels_by_unique_idx = (
    secret_labels.fillna("")
    .groupby("unique_idx")
    .aggregate(
        {
            "secret": list,
        }
    )
    .reset_index()
    .to_dict(orient="records")
)

# Load the evaluation dataset
vul_file_dir = f"./data/evaluation/evaluation-dataset"
files_to_scan = sorted(list(util.listdir(vul_file_dir)))

# Scan
scanner = ConfigScanner(os.getcwd())

offset = 0
results = []
for idx, path in enumerate(files_to_scan):

    parts = path.stem.split("_")
    unique_idx = int(parts[1])

    print(f"{idx + 1:,}/{len(files_to_scan):,}", end="\r")

    loaded = False
    vulnerable_file = dict()

    if not path.exists():
        print("File not exist")
    else:
        with open(path) as fin:
            try:
                vulnerable_file = yaml.safe_load(fin)
                loaded = True
            except Exception as e:
                print("Failed to load file as YAML")
                print(e)
                continue
    if not loaded:
        print("Failed to load file as YAML")
        continue

    string = "\n".join(util.load_str_list_from_file(path))

    scan_results = scanner.detect(string, vulnerable_file)

    if not scan_results:
        continue

    (
        chunks,
        comments,
        candidates_list,
        candidates_in_comments,
        valid_match,
        valid_match_in_comments,
        scanned_secrets,
    ) = scan_results

    temp = {
        "unique_idx": unique_idx,
        "scanned_secrets": scanned_secrets,
        "candidates_list": candidates_list,
        "candidates_in_comments": candidates_in_comments,
        "valid_match": valid_match,
        "valid_match_in_comments": valid_match_in_comments,
    }

    results.append(temp)


# Compare scan results with ground truth
tp = 0
fp = 0
fn = 0

for rst in sorted(labels_by_unique_idx, key=lambda x: x["unique_idx"]):
    unique_idx = rst["unique_idx"]
    matching_label_dicts = [d for d in results if d["unique_idx"] == unique_idx]

    scanned_secrets = []
    if len(matching_label_dicts) > 1:
        print("error")
        scanned_secrets = []
    elif len(matching_label_dicts) == 0:
        scanned_secrets = []
    elif len(matching_label_dicts) == 1:
        scanned_secrets = matching_label_dicts[0]["scanned_secrets"]

    ground_truth = [s for s in rst["secret"] if s]

    tp_cnt, fp_cnt, fn_cnt = util.compare_to_ground_truth(
        ground_truth, scanned_secrets
    )

    tp += tp_cnt
    fp += fp_cnt
    fn += fn_cnt


print(f"TP: {tp}, FP: {fp}, FN: {fn}")
print(f"Recall: {tp} / {tp + fn} = {tp / (tp + fn) * 100:.2f}")


# Expected output:

# TP: 304, FP: 577, FN: 35
# Recall: 304 / 339 = 89.68

# This result matches the recall rate of SecretScout mentioned in Section V.A
