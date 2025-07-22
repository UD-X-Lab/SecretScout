import re


def split_equal_sign(string) -> tuple[str, str]:
    parts = string.split("=")
    if len(parts) == 2:
        key = parts[0]
        value = parts[1]
        return (key, value)
    return ("", "")


def is_valid(
    key: str,
    value: str,
    known_fp_secret_names: list[str],
    known_fp_secrets: list[str],
) -> bool:

    if re.search(
        r"\$\{\{\s*(?:secrets|env)\.(?P<name>\S*)\s*\}\}",
        value,
        re.IGNORECASE,
    ):
        return False

    if re.search(r"^\d+:\d+$", value):
        return False

    if "@gmail.com" in value:
        return False

    known_fp_file_extensions = [".json", ".com", ".key"]
    if any([value.endswith(w) for w in known_fp_file_extensions]):
        return False

    full_str = f"{key}: {value}"
    if any([w.lower() in full_str.lower() for w in known_fp_secret_names]):
        return False

    if value in known_fp_secrets:
        return False

    if all([w in key.lower() for w in ["pub", "key"]]):
        return False

    adjusted = value.strip(r"\'\"")
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
            return True

        return False

    if adjusted.startswith("$"):
        return False

    if len(value) < 3:
        return False

    if special_match(key, r"[^0-9a-z_]"):
        return False

    if special_match(value, r"[^\$#<>@0-9a-z+:\-_.=]"):
        return False

    return True


def is_valid_in_log(
    key: str,
    value: str,
    known_fp_secret_names: list[str],
    known_fp_secrets: list[str],
) -> bool:
    if re.search(
        r"\$\{\{\s*(?:secrets|env)\.(?P<name>\S*)\s*\}\}",
        # full_str,
        value,
        re.IGNORECASE,
    ):
        return False

    if re.search(r"^\d+:\d+$", value):
        return False

    if "@gmail.com" in value:
        return False

    known_fp_file_extensions = [".json", ".com", ".key"]
    if any([value.endswith(w) for w in known_fp_file_extensions]):
        return False

    full_str = f"{key}: {value}"
    if any([w.lower() in full_str.lower() for w in known_fp_secret_names]):
        return False

    if value.lower() in known_fp_secrets:
        return False

    if all([w in key.lower() for w in ["pub", "key"]]):
        return False

    adjusted = value.strip(r"\'\"")
    # if m.startswith("${") and m.endswith("}"):
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
            return True

        return False

    if adjusted.startswith("$"):
        return False

    if len(value) < 3:
        return False

    if re.search(r"\.\S+$", value.lower()):
        return False

    if contain_only_dot_num(value.lower()):
        return False

    return True


def special_match(string, regex_str):
    search = re.compile(regex_str, re.IGNORECASE).search
    return bool(search(string))


def contain_only_dot_num(string):
    return not special_match(string, r"[^0-9\.]")
