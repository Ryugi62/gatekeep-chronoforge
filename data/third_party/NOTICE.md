# 제3자 자료 (비교 대상) — 전부 Apache-2.0, 2026-10-20 내려받음
- `gatekeep/adapters/baselines/third_party/rebuff_detect_pi_heuristics.py` — protectai/rebuff (https://github.com/protectai/rebuff), 무수정 복사.
- `data/third_party/*.yar` — deadbits/vigil-llm 의 YARA 규칙 4개 (https://github.com/deadbits/vigil-llm/tree/main/data/yara), 무수정 복사. 실행은 yara 엔진 대신 `re`로 옮긴 어댑터(`vigil_yara.py`)가 같은 패턴을 돌린다.
