## SecretScout

This repo contains the secret scanner described in our paper ***SecretScout: Effective Hard-coded Secrets Detection in CI Configuration Files***.

#### Steps to Run SecretScout

- Use the following command to extract the evaluation dataset:
  - `tar -xzf ./data/evaluation/evaluation-dataset.tar.gz -C ./data/evaluation/evaluation-dataset`
- Install the required libraries. Make sure `conda` is installed:
  - `conda env create -f environment.yml`
- Activate the virtual environment:
  - `conda activate SecretScout`
- Execute the following command to scan the evaluation dataset:
  - `python main.py`

#### Notes

- If you are interested in the preliminary study dataset, use the following command to extract it:
  - `tar -xzf ./data/prelim/prelim-dataset.tar.gz -C ./data/prelim/prelim-dataset`


#### BibTeX Entry
```bibtex
@inproceedings{chu2025secretscout,
  title     = {SecretScout: Effective Hard-coded Secrets Detection in CI Configuration Files},
  author    = {Qiao, Chu and Gu, Yacong and Li, Xiaofan and Gao, Xing},
  booktitle = {2025 44th International Symposium on Reliable Distributed Systems (SRDS)},
  year      = {2025},
}
```