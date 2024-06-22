#!/usr/bin/env python

import json
import sys


def print_entry(entry, key, max_length=64, continuation_prefix=".."):
    value = entry.get(key, "-")
    text = value if value else "-"
    first_line = True

    while len(text) > max_length:
        split_point = max_length
        print(text[:split_point])
        text = continuation_prefix + text[split_point:]
        if first_line is True:
            max_length += len(continuation_prefix)
            first_line = False
    print("{},".format(text))


def main(file_name):
    with open(file_name, 'r') as file:
        data = json.load(file)

    schema = [
        ("sk", 64),
        ("pk", 66),
        ("alpha", 64),
        ("ad", 64),
        ("h", 66),
        ("gamma", 66),
        ("beta", 64),
        ("proof_c", 64),
        ("proof_s", 64)
    ]
    print("----- SCHEMA -----")
    for (key, line_max) in schema:
        print(key)
    print("------------------\n")

    for entry in data:
        comment = entry.get("comment", "???")
        print("### {}".format(comment))
        print("\n```")
        for (key, line_max) in schema:
            print_entry(entry, key, line_max)
        print("```\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} <vectors.json>".format(sys.argv[0]))
        sys.exit(1)

    file_name = sys.argv[1]
    main(file_name)
