import argparse
import os
from pathlib import Path
import re

# from rule_handler.Rule._rule_pattern
rule_pattern = re.compile(
    r"^(?P<enabled>#)*[\s#]*"
    r"(?P<raw>"
    r"(?P<header>[^()]+)"
    r"\((?P<options>.*)\)"
    r"$)"
    )


def parse_rule_id(rule_line: str) -> str:
    gid_match = re.search(r'gid:(\d+);', rule_line)
    sid_match = re.search(r'sid:(\d+);', rule_line)
    rev_match = re.search(r'rev:(\d+);', rule_line)

    gid = gid_match.group(1) if gid_match else "1"
    sid = sid_match.group(1) if sid_match else ""
    rev = rev_match.group(1) if rev_match else "1"

    return f"{gid}:{sid}:{rev}"


def rule_file_normalize(snort2_input: str,
                        snort3_input: str,
                        snort2_output: str,
                        snort3_output: str,
                        remove_comment: bool) -> int:
    # Read rules from files and parse their ids.
    snort2_rules = {}
    with Path(snort2_input).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if rule_pattern.match(line):
                snort2_rules[parse_rule_id(line)] = line
    snort3_rules = {}
    with Path(snort3_input).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if rule_pattern.match(line):
                snort3_rules[parse_rule_id(line)] = line
    print(f"{len(snort2_rules)} rules in {snort2_input}")
    print(f"{len(snort3_rules)} rules in {snort3_input}")

    # Remove comment to activate the rule.
    if remove_comment:
        snort2_rules = {k: v.strip("# ") for k, v in snort2_rules.items()}
        snort3_rules = {k: v.strip("# ") for k, v in snort3_rules.items()}

    # Find the intersection.
    snort2_result = []
    snort3_result = []
    for rule_id, snort3_rule in snort3_rules.items():
        if rule_id in snort2_rules.keys():
            snort2_result.append(snort2_rules.get(rule_id))
            snort3_result.append(snort3_rule)
            snort2_rules.pop(rule_id)
        else:
            print(f"[snort3 rule] No matching rules in snort2_rules:")
            print(f"\t{snort3_rule}")
    for snort2_rule in snort2_rules.values():
        print(f"[snort2 rule] No matching rules in snort3_rules:")
        print(f"\t{snort2_rule}")

    # Write rules to new files.
    with Path(snort2_output).open("w", encoding="utf-8") as f:
        for line in snort2_result:
            f.write(line + "\n")
    with Path(snort3_output).open("w", encoding="utf-8") as f:
        for line in snort3_result:
            f.write(line + "\n")

    assert len(snort2_result) == len(snort3_result)
    return len(snort3_result)


def default_output(input_file_path: str, dir_name: str) -> str:
    # TODO: root path needed to avoid the difference between executing by pycharm and shell
    normalized_rules_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "resources",
        "normalized_rules",
        dir_name
    )
    if not os.path.exists(normalized_rules_path):
        os.makedirs(normalized_rules_path)

    return os.path.join(normalized_rules_path, os.path.basename(input_file_path))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A script to find rules that exist in both two files.")

    parser.add_argument('snort2_input', type=str)
    parser.add_argument('snort3_input', type=str)
    parser.add_argument('--snort2_output', type=str)
    parser.add_argument('--snort3_output', type=str)
    parser.add_argument('--remove_comment', action='store_true')

    args = parser.parse_args()

    snort2_rule_file_path = args.snort2_input
    snort3_rule_file_path = args.snort3_input
    snort2_rule_file_output_path = args.snort2_output if args.snort2_output else default_output(
        snort2_rule_file_path, "snort2")
    snort3_rule_file_output_path = args.snort3_output if args.snort3_output else default_output(
        snort3_rule_file_path, "snort3")

    print(f"Processing ...")

    normalized_rule_num = rule_file_normalize(snort2_rule_file_path,
                                              snort3_rule_file_path,
                                              snort2_rule_file_output_path,
                                              snort3_rule_file_output_path,
                                              args.remove_comment)

    print(f"{snort2_rule_file_path} => {snort2_rule_file_output_path}")
    print(f"{snort3_rule_file_path} => {snort3_rule_file_output_path}")
    print(f"{normalized_rule_num} normalized rules")
