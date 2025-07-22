import copy
import re
from pathlib import Path

import bashlex
from func_timeout import FunctionTimedOut, func_set_timeout, func_timeout

# from LogScanner import LogMatch
# from src.ConfigScanner import Match

common_template = r"\$[^\$\s]+"
double_brace_template = r"\$\{\{.*?\}\}"
single_brace_template = r"\$\{.*?\}"

common_pattern = r"\$[^\$\s]+"
double_brace_pattern = r"\$\{\{.*?\}\}"
single_brace_pattern = r"\$\{.*?\}"


def load_str_list_from_file(path: Path | str) -> list[str]:
    with open(path, "r") as fin:
        lines = fin.readlines()

    return [p for l in lines if (p := l.strip())]


def listdir(x: Path | str, max_depth=100):  # -> list[Path]:
    x = Path(x) if isinstance(x, str) else x

    if x.is_file() or max_depth == 0:
        yield x
    elif x.is_dir():
        for p in x.iterdir():
            yield from listdir(p, max_depth - 1)


def traverse_dict(data, path=None):
    if not path:
        path = []
    if isinstance(data, dict):
        for key in data.keys():
            local_path = path[:]
            local_path.append(key)
            for b in traverse_dict(data[key], local_path):
                yield b
    elif isinstance(data, list):
        for item in data:
            for b in traverse_dict(item, path):
                yield b
    else:
        yield path, data


def split_command_recursive(command):
    parts = list(bashlex.split(command))
    for p in parts:
        if len(list(bashlex.split(p))) > 1:
            yield from split_command_recursive(p)
        else:
            yield p


def find_all_word_node(root):
    if root.kind in ["word", "assignment"]:
        yield root
    elif root.kind in [
        "pipe",
        "operator",
        "parameter",
        "tilde",
        "reservedword",
    ]:
        pass
    elif root.kind == "redirect":
        if root.output not in [1, 2]:
            yield root.output
        else:
            pass
    elif root.kind == "compound":
        for ast in root.list:
            yield from find_all_word_node(ast)
    elif root.kind in ["commandsubstitution", "processsubstitution"]:
        for ast in root.command.parts:
            yield from find_all_word_node(ast)
    else:
        for ast in root.parts:
            yield from find_all_word_node(ast)


def list_cmd_parts(word_nodes: list, cmd):
    cmd_parts = []
    for node in word_nodes:
        if len(node.parts) == 0:
            cmd_parts.append(node.word)
        elif len(node.parts) == 1 and node.parts[0].kind == "parameter":
            cmd_parts.append(node.word)
        elif len(node.parts) == 1 and node.parts[0].kind == "tilde":
            cmd_parts.append(node.word)
        else:
            start, end = node.pos
            total_len = end - start
            word = cmd
            pos_list = []
            for idx, n in enumerate(node.parts):
                pos_list.append((idx, n.pos))
            pos_list = sorted(pos_list, key=lambda x: x[0], reverse=True)
            sub_len = 0
            for idx, (s, e) in pos_list:
                word = word[:s] + f"VAR{idx}" + word[e:]
                sub_len += e - s
            if total_len - sub_len > 2:
                cmd_parts.append(word[start : s + 5])
            temp_parts = []
            for n in node.parts:
                temp_parts += list(find_all_word_node(n))

            for n in temp_parts:
                cmd_parts.append(n.word)

    return cmd_parts


def gen_cmd_parts_bashlex_parse(cmd: str):
    try:
        nodes = func_timeout(5, bashlex.parse, args=(cmd))
    except FunctionTimedOut:
        return []
    except Exception as e:
        return []

    word_nodes = list(find_all_word_node(nodes[0]))
    return list_cmd_parts(word_nodes, cmd)


def gen_cmd_parts_bashlex_split(cmd):
    try:
        parts = list(split_command_recursive(cmd))
        return parts
    except:
        return []


def get_cmd_parts(cmd: str) -> list:
    parts = gen_cmd_parts_bashlex_parse(cmd)

    if not parts:
        try:
            parts = func_timeout(5, gen_cmd_parts_bashlex_split, args=(cmd))
        except FunctionTimedOut:
            parts = []
        except Exception as e:
            parts = []

    if not parts:
        parts = cmd.split()

    if not parts:
        return []

    return parts


def is_command(string: str) -> tuple[bool, list]:

    if len(string.split()) == 1:
        return False, []

    parts = get_cmd_parts(string)

    if parts and len(parts) > 1:
        return True, parts

    return False, []


def compare_to_ground_truth(
    ground_truth, scanned_secrets
) -> tuple[int, int, int]:

    tp_cnt = 0
    fn_cnt = 0
    fp_cnt = 0

    len_true_secrets = len(ground_truth)
    len_scanned_secrets = len(scanned_secrets)
    if len_scanned_secrets == 0 and len_true_secrets == 0:
        return tp_cnt, fp_cnt, fn_cnt
    if len_scanned_secrets > 0 and len_true_secrets == 0:
        return tp_cnt, len_scanned_secrets, fn_cnt
    if len_scanned_secrets == 0 and len_true_secrets > 0:
        return tp_cnt, fp_cnt, len_true_secrets

    copy_ground_truth = copy.deepcopy(ground_truth)
    for i in range(len_scanned_secrets):
        # if x == 2:
        x = scanned_secrets[i]
        if x in copy_ground_truth:
            tp_cnt += 1
            copy_ground_truth.remove(x)
        else:
            fp_cnt += 1

    fn_cnt = len(copy_ground_truth)

    return tp_cnt, fp_cnt, fn_cnt


def get_comments_in_line(string: str) -> str:
    rst = re.search(r"#.*$", string)
    if rst:
        start, end = rst.span()
        return rst.string[start:end]

    return ""
