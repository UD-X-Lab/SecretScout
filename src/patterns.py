import re

url_regex = r"//\S+:(\S{2,600})@"
url_pattern = re.compile(url_regex, re.IGNORECASE)

github_regex = r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b"
github_pattern = re.compile(github_regex, re.IGNORECASE)

webhook_regex = [
    r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{23,25})",
]
webhook_pattern = re.compile(rf"({'|'.join(webhook_regex)})", re.IGNORECASE)

patterns = {
    "url": url_pattern,
    "github": github_pattern,
    "webhook": webhook_pattern,
}
