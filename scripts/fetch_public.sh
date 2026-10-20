#!/bin/sh
# 공개 세트 내려받기 (가입·키 불필요). 결과는 data/raw/ (git 제외).
set -e
mkdir -p data/raw && cd data/raw
B=https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data
for f in test_cases_dh_base.json test_cases_ds_base.json user_cases.jsonl; do curl -sL "$B/$f" -o "$f"; done
python3 - <<'PY'
import json, urllib.request
rows = []
for sp in ("train", "test"):
    for off in range(0, 600, 100):
        u = "https://datasets-server.huggingface.co/rows?dataset=deepset/prompt-injections&config=default&split=%s&offset=%d&length=100" % (sp, off)
        rows += [(r["row"]["text"], r["row"]["label"]) for r in json.load(urllib.request.urlopen(u)).get("rows", [])]
json.dump(rows, open("deepset_all.json", "w"))
print(len(rows))
PY
