"""[실행하지 않음 — 강의실 PC 전용 실행카드] 딥러닝 주입 분류기를 같은 입력에 돌려 results/compare_deberta.csv 를 만든다.
맥에서는 돌리지 않는다(사용자 규칙: 맥에 딥러닝 설치 금지). 강의실 PC(아나콘다)에서 필요한 패키지를 설치한 뒤 실행한다.
모델: protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0). 학습 없음, 추론만."""
import csv
import json
import os

from transformers import pipeline  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
clf = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2", truncation=True, max_length=512)


def flags(text):
    return bool(text) and clf(text)[0]["label"] == "INJECTION"


rows = [json.loads(x) for x in open(os.path.join(ROOT, "data/cases.jsonl"), encoding="utf-8")]
with open(os.path.join(ROOT, "results/compare_deberta.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["id", "label", "deberta"])
    for c in rows:
        w.writerow([c["id"], c["label"], int(flags(c["user_request"]) or flags(c["untrusted_content"]))])
