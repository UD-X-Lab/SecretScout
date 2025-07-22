import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass

import pandas as pd

import src.filter_util as filter_util
import src.util as util
from src.filter_util import is_valid
from src.LogScanner import MatchTuple

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
class Match:
    type: str
    key_path: tuple
    value: str

    match: re.Match | str | tuple
    secret: str = ""

    location: tuple[int, int, int] = (-1, -1, -1)


class ConfigScanner:
    def __init__(
        self,
        project_root_path,
        scan_comments=False,
        DEBUG=False,
    ) -> None:
        self.DEBUG = DEBUG
        self.scan_comments = scan_comments
        self.filter_stopwords = ["uses", "name"]
        self.run_block_stopwords = ["ref"]
        self.known_fp_secret_names = [
            k.lower()
            for k in Counter(
                util.load_str_list_from_file(
                    f"{project_root_path}/src/known_fp_secret_names.txt"
                )
            ).keys()
        ]
        self.known_fp_secrets = [
            k
            for k in Counter(
                util.load_str_list_from_file(
                    f"{project_root_path}/src/known_fp_secrets.txt"
                )
            ).keys()
        ]
        self.notable_fp_stopwords = []

        from src.patterns import patterns

        self.patterns = patterns

    def log(self, s):
        if self.DEBUG:
            print(s)

    def load_regex_rules(self, rules_path):
        with open(rules_path) as fin:
            self.rules = json.load(fin)

    def generate_chunks_config(self, yaml_dict: dict) -> list:
        if not isinstance(yaml_dict, dict):
            return []
        if "jobs" not in yaml_dict.keys():
            return []

        chunks = []
        jobs: dict = yaml_dict["jobs"]

        if "env" in yaml_dict.keys():
            chunks.append((["env"], "env", yaml_dict["env"]))

        for name, job in jobs.items():
            for keyword, content in job.items():
                match keyword:
                    case "services":
                        for k, v in content.items():
                            chunks.append(
                                (["jobs", name, keyword], "service", v)
                            )
                    case "steps":
                        for item in content:
                            chunks.append(
                                (["jobs", name, keyword], "step", item)
                            )
                    case "permissions":
                        continue
                    case _:
                        chunks.append(
                            (["jobs", name, keyword], keyword, content)
                        )
        return chunks

    def get_comments(self, content_str: str) -> list[str]:
        rst = []
        lines = content_str.split("\n")
        for l in lines:
            comment = util.get_comments_in_line(l)
            if comment:
                rst.append(comment)

        return rst

    def search_secret(
        self, chunk_idx: int, key_path, value, pattern: re.Pattern
    ) -> list[Match]:
        self.log("-------- start: search_secret --------")
        candidates = []
        string = f"{key_path[-1]}: {value}"
        self.log(string)

        matches = pattern.finditer(string)
        matches = [m for m in matches]
        if len(matches) > 0:
            valid: list[re.Match] = [m for m in matches if any(m.groups())]
            if len(valid) > 0:
                for m in valid:
                    candidates.append(
                        Match(
                            "regex",
                            tuple(key_path),
                            value,
                            m,
                            m.groups()[0].strip(r"\'\""),
                            (chunk_idx, -1, -1),
                        )
                    )
        self.log("-------- end: search_secret --------")
        return candidates

    def search_password_in_commands(
        self,
        chunk_idx: int,
        cmd_idx: int,
        key_path: list[str],
        cmd_parts: list[str],
        keywords,
    ) -> list[Match]:
        self.log("-------- start: search_password_in_commands --------")
        rst: list[Match] = []
        known_fp_cmd = [
            "mkdir",
            "docker",
            "mvn",
            "mypy",
            "go",
            "cargo",
            "gcov-9",
            "vendor/bin/phpcs",
            "git",
            "./gradlew",
            "./mvnw",
            "ghp-import",
        ]
        if len(cmd_parts) == 1:
            init_cmd_list = [cmd_parts[0]]
        else:
            init_cmd_list = [cmd_parts[0], cmd_parts[1]]

        command = " ".join(cmd_parts)

        curr_idx = 0
        while curr_idx < len(cmd_parts):
            curr_arg = cmd_parts[curr_idx]
            self.log("-" * 80)
            self.log(f"{curr_idx}, {curr_arg}")

            is_command, subparts = util.is_command(curr_arg)
            if is_command:
                self.log(f">>> Current arg is command. curr arg: {curr_arg}")
                rst += self.search_password_in_commands(
                    chunk_idx, cmd_idx, key_path, subparts, keywords
                )
                continue

            if curr_arg.lower() == "-p":
                self.log(f">>> flag -p")
                if any([arg in known_fp_cmd for arg in init_cmd_list]):
                    curr_idx += 1
                    continue

                try:
                    next_arg = cmd_parts[curr_idx + 1]
                except:
                    next_arg = None

                if next_arg and not next_arg.startswith("-"):

                    rst.append(
                        Match(
                            "command_p_flag",
                            tuple(key_path),
                            command,
                            ("-p", next_arg),
                            next_arg.strip(r"\'\""),
                            (chunk_idx, cmd_idx, curr_idx),
                        )
                    )
                    curr_idx += 1

            elif curr_arg.lower() == "-u" and cmd_parts[0] == "curl":
                self.log(f">>> flag -u")

                try:
                    next_arg = cmd_parts[curr_idx + 1]
                except:
                    next_arg = None
                if next_arg and ":" in next_arg:
                    parts = next_arg.split(":")
                    key = parts[0].strip().lower()
                    value = parts[1].strip()
                    rst.append(
                        Match(
                            "command_u_flag",
                            tuple(key_path),
                            command,
                            ("-u", next_arg),
                            value.strip(r"\'\""),
                            (chunk_idx, cmd_idx, curr_idx),
                        )
                    )
                    curr_idx += 1
            elif (
                (search_rst := re.match(r"^-[pP](?P<pw>.*)", curr_arg))
                and "=" not in curr_arg
                and curr_arg.lower() != "-password"
            ):  # fmt: skip
                self.log(f">>> flag -[Pp]<pass>")
                known_fp_flags = [
                    "-path",
                    "-parallel",
                    "-passthru",
                    "Get-Physicaldisk",
                    "-Physicaldisks",
                    "-print",
                    "-password",
                    "-project",
                    "-property",
                    "-properties",
                    "-printf",
                    "-print0",
                    "-prod",
                    "-print-log",
                    "-production",
                    "-proc",
                    "-process",
                    "-perm",
                    "-prune",
                    "-params",
                    "-pkg",
                    "-prerelease",
                ]
                known_fp_flags = [w.lower() for w in known_fp_flags]
                if curr_arg.lower() in known_fp_flags:
                    curr_idx += 1
                    continue

                if any([arg in known_fp_cmd for arg in init_cmd_list]):
                    curr_idx += 1
                    continue
                if search_rst.group("pw"):
                    rst.append(
                        Match(
                            "command_Psec_flag",
                            tuple(key_path),
                            command,
                            ("-p", search_rst.group("pw")),
                            search_rst.group("pw").strip(r"\'\""),
                            (chunk_idx, cmd_idx, curr_idx),
                        )
                    )
            elif curr_arg.startswith("-") and "=" in curr_arg:
                self.log(f">>> -|--flag=VAR")
                parts = curr_arg.split("=")
                key = parts[0].strip().lower()
                value = parts[1].strip()
                if any([kw in key for kw in keywords]):
                    rst.append(
                        Match(
                            "command",
                            tuple(key_path),
                            command,
                            (key, value),
                            value.strip(r"\'\""),
                            (chunk_idx, cmd_idx, curr_idx),
                        )
                    )
            elif (
                curr_arg.startswith("-")
                and any([kw in curr_arg.lower() for kw in keywords])
            ):  # fmt: skip
                self.log(f">>> -|--flag VAR")
                try:
                    next_arg = cmd_parts[curr_idx + 1]
                except:
                    next_arg = None
                if next_arg and not next_arg.startswith("-"):
                    rst.append(
                        Match(
                            "command",
                            tuple(key_path),
                            command,
                            (curr_arg, next_arg),
                            next_arg.strip(r"\'\""),
                            (chunk_idx, cmd_idx, curr_idx),
                        )
                    )
                    curr_idx += 1
            elif "=" in curr_arg and "==" not in curr_arg:
                self.log(">>> = in argument")
                parts = curr_arg.split("=")
                key = parts[0].strip().lower()
                value = parts[1].strip()
                self.log(f"{key} | {value}")
                if any([kw in key for kw in keywords]):
                    rst.append(
                        Match(
                            "command",
                            tuple(key_path),
                            command,
                            (key, value),
                            value.strip(r"\'\""),
                            (chunk_idx, cmd_idx, curr_idx),
                        )
                    )
            elif (
                any([kw in curr_arg.lower() for kw in keywords])
                and curr_arg.endswith(":")
            ) or (curr_arg.lower() in keywords):
                self.log("keywords in current arguments")
                if curr_arg.lower() == "login" and not any(
                    [arg.lower() == "mvn" for arg in init_cmd_list]
                ):
                    curr_idx += 1
                    continue
                try:
                    next_arg = cmd_parts[curr_idx + 1]
                except:
                    next_arg = None
                if next_arg and not next_arg.startswith("-"):
                    rst.append(
                        Match(
                            "command_kw_in_curr_arg",
                            tuple(key_path),
                            command,
                            (curr_arg, next_arg),
                            next_arg.strip(r"\'\""),
                            (chunk_idx, cmd_idx, curr_idx),
                        )
                    )
                    curr_idx += 1

            curr_idx += 1

        self.log("-------- end: search_password_in_commands --------")
        return rst

    def scan_chunk_simplified(self, data):
        self.log("-------- start: scan_chunk_simplified --------")

        path_to_chunk, _, chunk = data
        if (
            isinstance(chunk, dict)
            and "uses" in chunk.keys()
            and "cache" in chunk["uses"]
        ):
            return

        if (
            isinstance(chunk, dict)
            and "uses" in chunk.keys()
            and "hashicorp/vault-action" in chunk["uses"]
        ):
            chunk["with"].pop("secrets")

        tree_paths = list(util.traverse_dict(chunk))

        candidates: list[Match] = []
        key_path: list[str]
        value: str
        for chunk_idx, (key_path, value) in enumerate(tree_paths):
            key = key_path[-1] if len(key_path) > 0 else path_to_chunk[-1]
            key = key.lower()
            adjusted_path = key_path if len(key_path) > 0 else path_to_chunk

            if any([kw in key for kw in KEYWORDS]):
                candidates.append(
                    Match(
                        "key-value",
                        tuple(adjusted_path),
                        value,
                        value,
                        str(value).strip(r"\'\""),
                        (chunk_idx, -1, -1),
                    )
                )

            elif key == "run":
                commands = [
                    s.strip(" \\")
                    for s in value.split("\n")
                    if s and not s.startswith("#")
                ]
                for cmd_idx, cmd in enumerate(commands):
                    self.log(f"curr cmd: {cmd_idx} {cmd}")
                    if cmd in ["fi", "done", "esac", "else", "else if", "'"]:
                        continue
                    self.log(f"curr cmd after strip(): {cmd}")

                    parts = util.get_cmd_parts(cmd)
                    if not parts:
                        continue

                    self.log(f"cmd parts: {parts}")

                    matches = self.search_password_in_commands(
                        chunk_idx, cmd_idx, adjusted_path, parts, KEYWORDS
                    )
                    if len(matches) > 0:
                        candidates += matches
            elif (
                isinstance(value, str)
                and " -p" in value.lower()
                and not " --p" in value.lower()
            ):
                commands = [
                    cmd.strip()
                    for cmd in value.split("\n")
                    if cmd
                    and " -p" in cmd.lower()
                    and not " --p" in cmd.lower()
                ]
                for cmd_idx, cmd in enumerate(commands):
                    parts = util.get_cmd_parts(cmd)
                    if not parts:
                        continue

                    self.log(f"cmd parts: {parts}")

                    matches = self.search_password_in_commands(
                        chunk_idx, cmd_idx, adjusted_path, parts, KEYWORDS
                    )
                    if len(matches) > 0:
                        candidates += matches

            gha_token_prefix = [
                "ghp_",
                "gho_",
                "ghu_",
                "ghs_",
                "ghr_",
                "github_pat_",
            ]
            if (
                isinstance(value, str)
                and any([prefix in value for prefix in gha_token_prefix])
            ):  # fmt: skip
                candidates += self.search_secret(
                    chunk_idx, adjusted_path, value, self.patterns["github"]
                )

            if isinstance(value, str) and "//" in value:
                candidates += self.search_secret(
                    chunk_idx, adjusted_path, value, self.patterns["url"]
                )

            if "webhook" in key:
                candidates.append(
                    Match(
                        "key-value",
                        tuple(adjusted_path),
                        value,
                        value,
                        str(value).strip(r"\'\""),
                        (chunk_idx, -1, -1),
                    )
                )
            elif isinstance(value, str) and "http" in value and "hook" in value:
                candidates += self.search_secret(
                    chunk_idx, adjusted_path, value, self.patterns["webhook"]
                )

        self.log("-------- end: scan_chunk_simplified --------")
        if len(candidates) == 0:
            return
        else:
            return {
                "chunk": path_to_chunk,
                "candidates": candidates,
            }

    def remove_duplicate_candidates(self, candidates: dict):
        _, candidates_list = candidates.values()
        df = pd.DataFrame.from_records([asdict(m) for m in candidates_list])
        df["key_path_string"] = df["key_path"].apply(lambda x: "|".join(x))
        unique_idx = (
            df[["key_path_string", "value", "location"]].drop_duplicates().index
        )
        unique_df = df.iloc[unique_idx][
            ["type", "key_path", "value", "match", "secret", "location"]
        ]
        unique_match = unique_df.to_dict(orient="records")
        unique_match = [Match(*d.values()) for d in unique_match]

        return {
            "chunk": candidates["chunk"],
            "candidates": unique_match,
        }

    def filter(self, candidate: dict):
        self.log("-------- start: filter --------")
        valid_match = []
        c: Match
        for c in candidate["candidates"]:

            key_path = c.key_path
            value = c.value
            key = key_path[-1]
            m = c.match
            target_secret = c.secret
            self.log(f"{target_secret}")

            full_str = f"{key}: {value}"
            if re.search(
                r"\$\{\{\s*(?:secrets|env)\.(?P<name>\S*)\s*\}\}",
                target_secret,
                re.IGNORECASE,
            ):
                self.log("Filtered: ${{ }}")
                continue

            if re.search(r"^\d+:\d+$", target_secret):
                self.log("Filtered: port:port")
                continue

            if re.search(r"^\d{4}$", target_secret):
                self.log("Filtered: 4 digit number")
                continue

            if "@gmail.com" in target_secret:
                self.log("Filtered: email address")
                continue

            known_fp_file_extensions = [".json", ".com", ".key"]
            if any(
                [target_secret.endswith(w) for w in known_fp_file_extensions]
            ):
                self.log("Filtered: file extension")
                continue

            if any(
                [
                    w.lower() in full_str.lower()
                    for w in self.known_fp_secret_names
                ]
            ):
                self.log("Filtered: known secret name")
                continue

            if target_secret in self.known_fp_secrets:
                self.log("Filtered: known FP secrets")
                continue

            adjusted = target_secret.strip(r"\'\"")
            if adjusted.startswith("${") and adjusted.endswith("}"):
                secret = adjusted.strip("${}")
                gha_token_prefix = [
                    "ghp",
                    "gho",
                    "ghu",
                    "ghs",
                    "ghr",
                    "github_pat",
                ]
                if any([prefix in secret for prefix in gha_token_prefix]):
                    c.secret = secret.strip()
                    valid_match.append(c)
                continue

            if adjusted.startswith("$"):
                continue

            if len(target_secret) < 3:
                continue

            if isinstance(m, re.Match):
                start, end = m.span()
                matching_str = full_str[start:end]
                matching_grp_idx = matching_str.index(target_secret)

                if re.search(
                    r"\$\{\{\s*(?:secrets|env)\.(?P<name>\S*)\s*\}\}",
                    m.string,
                    re.IGNORECASE,
                ):
                    continue

                if matching_str[matching_grp_idx - 1] == "$":
                    continue

                if any([w in key_path for w in self.filter_stopwords]):
                    continue

                if all([w in key.lower() for w in ["pub", "key"]]):
                    continue

                if "u=" in matching_str:
                    continue

            elif isinstance(m, str) or isinstance(m, tuple):
                if isinstance(m, str):
                    matching_key: str = ""
                else:
                    matching_key: str = m[0]

                if all([w in matching_key.lower() for w in ["project", "key"]]):
                    continue

            if filter_util.special_match(
                target_secret,
                r"[^\$#<>@0-9a-z+:\-_.=]",
            ):
                continue
            valid_match.append(c)

        self.log("-------- end: filter --------")
        if len(valid_match) == 0:
            return
        else:
            return {"match": valid_match, "chunk": candidate["chunk"]}

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

                if any([kw in key for kw in KEYWORDS]):
                    candidates.append(
                        MatchTuple(idx, i, key, value.strip(r"\'\""))
                    )

                if "=" in key:
                    k, v = filter_util.split_equal_sign(key)
                    if any([kw in k.lower() for kw in KEYWORDS]):
                        candidates.append(
                            MatchTuple(idx, i, k, v.strip(r"\'\""))
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
            is_secret = is_valid(
                c.key, c.value, known_fp_secret_names, known_fp_secrets
            )
            if not is_secret:
                continue

            valid_match.append(c)

        return valid_match

    def detect(self, content_str: str, file_yaml_dict: dict):
        chunks = self.generate_chunks_config(file_yaml_dict)
        if not chunks:
            return None

        candidates_list = []
        for chunk in chunks:
            candidates = self.scan_chunk_simplified(chunk)
            if candidates:
                candidates_list.append(candidates)

        valid_match = []
        num_valid_match = 0
        for candidates in candidates_list:
            unique_candidates = self.remove_duplicate_candidates(candidates)
            valid = self.filter(unique_candidates)
            if valid:
                num_valid_match += len(valid["match"])
                valid_match.append(valid)

        candidates_in_comments = []
        unique_candidates_in_comments = []
        known_fp_secrets_log = [
            "for",
            "not",
            "Permissions",
            "FOR",
            ".hypothesis",
            "key",
            "***",
        ]
        valid_match_in_comments = []

        comments = self.get_comments(content_str)
        if self.scan_comments:
            for idx, line in enumerate(comments):
                candidates = self.scan_string_new_way(idx, line)
                if candidates:
                    candidates_in_comments += candidates

            unique_candidates_in_comments = self.remove_duplicates(
                candidates_in_comments
            )

            valid_match_in_comments = self.filter_MatchTuple(
                unique_candidates_in_comments,
                self.known_fp_secret_names,
                self.known_fp_secrets + known_fp_secrets_log,
            )

        num_valid_match += len(valid_match_in_comments)

        scanned_secrets = []
        for d in valid_match:
            for m in d["match"]:
                scanned_secrets.append(m.secret)
        for m in valid_match_in_comments:
            scanned_secrets.append(m.value)

        return (
            chunks,
            comments,
            candidates_list,
            candidates_in_comments,
            valid_match,
            valid_match_in_comments,
            scanned_secrets,
        )
