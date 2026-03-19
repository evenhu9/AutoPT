import argparse
import csv
import json
import re
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

def clean_text(s: str) -> str:
    s = ANSI_RE.sub("", s)
    s = s.replace("\r", " ").replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="输入 jsonl 文件路径")
    parser.add_argument("--output", default="", help="输出 tsv 文件路径（可选）")
    parser.add_argument("--max-cmd", type=int, default=8, help="最多展开多少个 commands 列")
    parser.add_argument("--max-hist", type=int, default=8, help="最多展开多少个 history 列")
    args = parser.parse_args()

    src = Path(args.input)
    dst = Path(args.output) if args.output else src.with_suffix(".wide.tsv")

    rows = []
    with src.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append(obj)

    headers = ["count", "flag", "runtime", "commands_len", "history_len"]
    headers += [f"command_{i+1}" for i in range(args.max_cmd)]
    headers += [f"history_{i+1}" for i in range(args.max_hist)]

    with dst.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(headers)

        for obj in rows:
            commands = obj.get("commands", []) or []
            history = obj.get("history", []) or []

            row = [
                obj.get("count", ""),
                obj.get("flag", ""),
                obj.get("runtime", ""),
                len(commands),
                len(history),
            ]

            for i in range(args.max_cmd):
                row.append(clean_text(str(commands[i])) if i < len(commands) else "")

            for i in range(args.max_hist):
                row.append(clean_text(str(history[i])) if i < len(history) else "")

            writer.writerow(row)

    print(f"done: {dst}")

if __name__ == "__main__":
    main()