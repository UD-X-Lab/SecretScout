import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from itertools import chain
from pathlib import Path

import src.filter_util as filter_util
import src.util as util

# project_root_path = "/home/jack/Documents/projects/ci-tools/ci-scanner"
# sys.path.append(project_root_path)

LOG_GENERIC_REGEX = [
    r"(?:token|key|password|pass|secret|passwd|sec|cred|auth)",
    r"(?:\s|=|>|:{1,3}=|\|\|:|<=|=>|:|\?=){1,2}",  # operator
    r"(?:\'|\\\'|\"|\x60|\{|\$|\s){0,5}",  # secretPrefix
    r"([!<>@0-9a-z\-_.=]{3,600})",  # secret itself
    r"(?:\'|\\\'|\"|\n|\r|\s|\x60|;|\}|$)",  # secretSuffix
]
LOG_GENERIC_PATTERN = re.compile("".join(LOG_GENERIC_REGEX), re.IGNORECASE)

KEYWORDS = [
    "token",
    "key",
    "password",
    "pass",
    "secret",
    "passwd",
    "sec",
    "cred",
    "auth",
    "login",
    "client",
]


@dataclass(unsafe_hash=True)
class LogMatch:
    location: int
    platform: str
    original_str: str
    start: int
    end: int
    matching_str: str
    secret: str


@dataclass(unsafe_hash=True)
class MatchTuple:
    row: int
    col: int
    key: str
    value: str


class LogScanner:
    def __init__(self, DEBUG=False) -> None:
        self.DEBUG = DEBUG
        # self.load_regex_rules(
        #     f"{project_root_path}/data/all_rules_py_regex.json"
        # )
        self.filter_stopwords = ["uses", "name"]
        self.run_block_stopwords = ["ref"]
        self.known_fp_secret_names = [
            k.lower()
            for k in Counter(
                util.load_str_list_from_file(
                    f"{project_root_path}/data/known_fp_secret_names.txt"
                )
            ).keys()
        ]
        self.known_fp_secrets = [
            k
            for k in Counter(
                util.load_str_list_from_file(
                    f"{project_root_path}/data/known_fp_secrets.txt"
                )
            ).keys()
        ]
        self.notable_fp_stopwords = []

        from patterns import patterns

        self.patterns = patterns

    def log(self, s):
        if self.DEBUG:
            print(s)

    def load_regex_rules(self, rules_path):
        with open(rules_path) as fin:
            self.rules = json.load(fin)

    def process_log(self, log_path: Path | str) -> list[str]:

        lines = util.load_str_list_from_file(log_path)
        processed = [line[28:].strip() for line in lines]

        return processed

    def scan_string(
        self, idx: int, string, pattern_name: str, pattern: re.Pattern
    ) -> list[LogMatch]:
        self.log("-------- start: search_secret --------")
        candidates = []
        matches = pattern.finditer(string)
        matches = [m for m in matches]
        if len(matches) > 0:
            valid: list[re.Match] = [m for m in matches if any(m.groups())]
            if len(valid) > 0:
                for m in valid:
                    start, end = m.span()
                    candidates.append(
                        LogMatch(
                            idx,
                            pattern_name,
                            string,
                            start,
                            end,
                            m.string[start:end],
                            m.groups()[0],
                        )
                    )
        self.log("-------- end: search_secret --------")
        return candidates

    def scan_string_new_way(self, idx: int, string: str) -> list[MatchTuple]:
        candidates = []

        if len(string) == 0:
            return candidates

        parts = string.split()
        num_parts = len(parts)
        if num_parts == 1:
            if parts[0].endswith(":"):
                return candidates
            if "=" in parts[0]:
                k, v = filter_util.split_equal_sign(parts[0])
                if any([kw in k.lower() for kw in KEYWORDS]):
                    candidates.append(MatchTuple(idx, 0, k, v.strip(r"\'\"")))
        else:
            for i in range(num_parts - 1):
                key = parts[i].lower()
                value = parts[i + 1]

                if "=" in key:
                    k, v = filter_util.split_equal_sign(key)
                    if any([kw in k.lower() for kw in KEYWORDS]):
                        candidates.append(
                            MatchTuple(idx, i, k, v.strip(r"\'\""))
                        )

                if not key.endswith(":"):
                    continue

                if any([kw in key for kw in KEYWORDS]):
                    candidates.append(
                        MatchTuple(idx, i, key, value.strip(r"\'\""))
                    )

            if "=" in parts[-1]:
                k, v = filter_util.split_equal_sign(parts[-1])
                if any([kw in k.lower() for kw in KEYWORDS]):
                    candidates.append(
                        MatchTuple(idx, num_parts - 1, k, v.strip(r"\'\""))
                    )

        return candidates

    def remove_duplicates(
        self, candidates: list[MatchTuple]
    ) -> list[MatchTuple]:
        return candidates

    def filter_MatchTuple(
        self,
        candidates: list[MatchTuple],
        known_fp_secret_names: list[str],
        known_fp_secrets: list[str],
    ) -> list[MatchTuple]:
        valid_match: list[MatchTuple] = []

        for c in candidates:
            is_secret = filter_util.is_valid_in_log(
                c.key, c.value, known_fp_secret_names, known_fp_secrets
            )
            if not is_secret:
                continue

            valid_match.append(c)

        return valid_match

    def detect(self, log_path: Path | str):
        processed = self.process_log(log_path)
        candidates_list = []
        for idx, line in enumerate(processed):
            candidates = self.scan_string_new_way(idx, line)
            if candidates:
                candidates_list += candidates

        known_fp_secrets_log = [
            "for",
            "not",
            "Permissions",
            "FOR",
            ".hypothesis",
            "key",
            "***",
        ]
        valid_match = self.filter_MatchTuple(
            candidates_list,
            self.known_fp_secret_names,
            self.known_fp_secrets + known_fp_secrets_log,
        )

        scanned_secrets = []
        for m in valid_match:
            scanned_secrets.append(m.value)

        return candidates_list, valid_match, scanned_secrets
