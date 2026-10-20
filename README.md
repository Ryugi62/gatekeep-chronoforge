# GateKeep: a checkpoint that stops hijacked AI agents before they act

**English summary (for judges).** GateKeep sits between a city-service AI agent and its tools. Before a tool runs (payment, e-mail, file delete, external share, permission grant) it checks that single call against the citizen's own request with six fixed rules (R0-R5) and, if it blocks, writes the reason as an evidence line. No model, no training, no LLM call at runtime. It is a student, lightweight implementation of the same idea that Invariant Guardrails, Progent, CaMeL, AgentDojo's `tool_filter`, LlamaFirewall and Lakera Agent Behavior Defense pursue; our contribution is a small auditable rule set, a city tool pack and a public measurement, not a new idea.

- **Measured on 146 cases** (81 attacks, 65 normal; AgentDojo + deepset + our own): blocks 75/81 attacks (92.6%), wrongly blocks 5/65 normal calls (7.7%); without the scope rule R1 it blocks 52/81 (64.2%). p95 check time is far below 5 ms. Two open-source text-only components (Rebuff heuristics, four Vigil YARA rules) block 2/81. Full table, method and limits: [results/compare.md](results/compare.md).
- **New in v3: R1 without the oracle.** `gatekeep/domain/intent.py` derives the allowed tools from the user's request sentence alone (rule-based verb and object dictionary in English and Korean, negation handled, no model, no LLM, no training), so the allow-list no longer has to be declared. Both modes on the same input: 146 cases, oracle R1 blocks 75/81 attacks and wrongly blocks 5/65 normal calls (7.7%), request-derived R1 blocks 75/81 and wrongly blocks 7/65 (10.8%); hand-written city-service set (26 indirect-injection attacks + 9 normal tasks, `data/city_attacks.jsonl`), both modes block 23/26 with 0/9 false positives (the 3 misses are deliberate known limits; without R1 it is 22/26). The derived mode costs 3.1 points of false positives on the 146 cases (tasks whose sentence does not reveal the tool they need) and we did not tighten the dictionary to hide that. The 146 cases served as the dictionary's development set; the hand set was written first and not tuned against. Threat model in 3 lines: the attacker can plant text in anything the agent reads but cannot change the user's request or the gate; trusted = the user's request and the operator's city pack, untrusted = all other text and the tool arguments the model produced; out of scope = a runtime that lies about the request, body tampering to an allowed recipient, read-only exfiltration, and how often a real LLM is fooled in general (v4 gives a first small measurement, see below). Demo: tick the new checkbox to derive the allow-list from the request.
- **New in v4: an untouched set and real LLMs.** (1) After freezing the code (commit 30336c9) we wrote 18 new city-service indirect-injection attacks and 13 normal tasks (`data/city_holdout.jsonl`), committed them before measuring, and changed no rule afterwards (a test checks that `gatekeep/domain` is unchanged since the freeze). Oracle R1 and request-derived R1 both block 16/18 attacks (88.9%, Wilson 95% 67-97%) and wrongly block 0/13 normal tasks (0-23%); the two misses are the deliberate known limits (body tampering to an allowed recipient, in-limit amount tampering). (2) Real LLMs as the attacked agent (GateKeep itself still uses no LLM): the same 18 attack and 13 normal tasks went to free-tier Gemini models (gemini-2.5-flash 8 attack tasks, gemini-3.5-flash 5, gemini-3.1-flash-lite 5 plus all normal tasks; the free tier allows 20 requests per model per day, so the work was split, wording of the limit in `results/compare.md` section 12; one run per task, temperature 0, no security warning in the agent prompt). The agent read the injected text in 14 of 18 tasks and attempted a dangerous call in 7 of 18 (39%; 3/8, 0/5, 4/5 by model). GateKeep with request-derived R1 stopped 4 of those 7 (oracle R1: 5 of 7); the 3 calls that still ran were the two known limits and one case where the model picked `share_file` instead of `send_email` (recipient "clerk", not the attacker's). 0/13 normal tasks were blocked and 1 was held for confirmation (the pointed-to bill). n is small, three models are mixed, one run each: a first measurement, not a rate. Raw data: `results/llm_runs.jsonl`; reproduce with `GEMINI_API_KEY=... python3 -m gatekeep.infrastructure.llm_bench`.
- **Read the numbers with these caveats.** The allow-list used by R1 is taken from AgentDojo's ground-truth calls (an oracle); the normal tasks' tool responses are filler sentences, not the real files, so the 7.7% is probably an underestimate; the 146-case and city-set attack calls assume the agent was fooled; only the v4 real-LLM table measures what a model actually does, on 18 tasks.
- **Independent red-team fixes (v2).** A red team broke v1 three times out of three (renamed tool `wire_funds` was treated as a read; destination key `beneficiary_iban` and a space-split account number slipped through; Aadhaar/PAN numbers could be mailed out; `rm -r -f /` was not recognised; the bill-payment scene was blocked). v2 denies tools it cannot place (R0), matches destinations by normalized whole token and by argument-name patterns, recognises split shell flags and `run_command`, adds Aadhaar/PAN formats to R5, and introduces a CONFIRM verdict for values read from a document the user pointed to. On the 21-case red-team set v1 stopped 2 of 15 attacks and wrongly blocked 3 of 6 normal or bill-scene calls; v2 meets all expectations. That set was written after the bypasses were known, so it is a regression test, not evidence of general strength.
- **Try it:** `python3 -m pytest -q`, `python3 scripts/demo.py`, or the static demo at https://ryugi62.github.io/gatekeep-chronoforge/demo/ (no login, no server).
- **Authorship:** AI-assisted (Claude, Anthropic); the team lead reviewed the result. Third-party assets are listed under "Sources and licenses".

---

# GateKeep — AI 에이전트 행동 검문소 (한국어 상세)

도시 서비스용 AI 에이전트가 **도구를 호출하기 직전**(송금·메일·파일 삭제·외부 전송·권한 부여)에 호출을 규칙으로 검문해 막고, 막은 이유(Evidence)를 감사 기록에 남긴다. 프롬프트 문장을 거르는 분류기가 아니라 **행동 단계 관문**이다. 에이전트가 속았더라도 위험한 행동은 실행되지 않는다.

- 스펙: [SPEC.md](SPEC.md) (유비쿼터스 언어 ToolCall·Checkpoint·Rule·Verdict·Evidence·CitedSource·CityPack, 숫자 성공 조건, Given/When/Then 11개, 비목표)
- 실측표: [results/compare.md](results/compare.md) · 원자료 [results/compare.csv](results/compare.csv)
- 저작 모드: AI 보조(Claude)로 코드를 작성했고 제작자가 검수했다. 제3자 자산은 아래 「출처」에 전부 밝힌다.

## 어떻게 막나 (규칙 6개, 판정은 ALLOW·CONFIRM·BLOCK)
| 규칙 | 막는 것 |
|---|---|
| R0 UnknownTool | 등록되지 않았고 이름 동사로 등급을 못 정한 도구 (기본 거부, 「모르는 이름 = 읽기」 아님) |
| R1 OutOfScope | 사용자 요청 범위 밖의 쓰기·송금·삭제·권한 도구 (최소 권한) |
| R2 TaintedDestination | 수신자·계좌·URL(인자 이름은 iban·account·beneficiary·to·email·url 등 패턴, 공백·하이픈 제거 후 전체 토큰 비교)이 사용자 요청에는 없고 신뢰할 수 없는 글에만 있는 호출. 사용자가 가리킨 문서에서만 나오면 CONFIRM |
| R3 AmountLimit | 상한(설정값, `data/city_pack.json`) 초과 금액이 사용자 요청에 없는 송금. 사용자가 가리킨 문서에서만 나오면 CONFIRM |
| R4 PathEscape | 작업 폴더 밖 삭제·`..`·위험 셸 명령(`rm -r -f /`, `run_command` 포함) |
| R5 SecretEgress | 외부 전송 인자에 들어간 API 키·개인 키·비밀번호 값, Aadhaar·PAN 형식(시민이 요청에 직접 쓴 번호 제외) |

```
python3 scripts/demo.py                          # 모의 도구 상자 시연: 정상 호출 통과, 주입된 cc 차단 + 감사 기록
python3 -m pytest -q                             # 테스트
sh scripts/fetch_public.sh                       # (선택) 공개 세트 다시 내려받기
python3 scripts/build_dataset.py                 # data/cases.jsonl 재생성 (시드 고정)
python3 scripts/build_city_attacks.py            # 손 공격 세트 data/city_attacks.jsonl 재생성
python3 scripts/build_city_holdout.py            # 미접촉 세트 data/city_holdout.jsonl (코드 고정 30336c9 뒤 작성)
GEMINI_API_KEY=... python3 -m gatekeep.infrastructure.llm_bench   # 실제 LLM 소규모 실측 (무료 등급, 키는 환경변수로만)
python3 -m gatekeep.infrastructure.bench         # 실측표 재생성 (오라클 R1·자동 추출 R1 두 모드 포함) (Rebuff 휴리스틱 때문에 1~2분)
```
Python 3.9 표준 라이브러리만 쓴다(테스트만 pytest). GateKeep 자체는 LLM 호출·학습 없음(실측 도구 `llm_bench`의 LLM은 검문 대상인 에이전트).

## 구조 (의존 방향 domain ← application ← adapters ← infrastructure)
```
gatekeep/domain/          순수 판정: model.py rules.py checkpoint.py intent.py(요청 문장→허용 도구 추출)  (I/O·프레임워크 모름)
gatekeep/application/     GuardToolCall 유스케이스 + 포트(AuditLog, TextGuard) + agent_episode.py(LLM 에이전트 한 판, 포트 AgentSession)
gatekeep/adapters/        gate.py(동작 관문) audit_jsonl.py tool_registry.py cases.py baselines/(비교 대상) gemini_agent.py city_tools.py(모의 도구)
gatekeep/infrastructure/  bench.py(실측 실행기) metrics.py llm_bench.py(실제 LLM 실측)
```

## 기존 코드와 신규 개발 범위
| 구분 | 내용 |
|---|---|
| 기존(제작자의 개인 에이전트 운영 환경, **이 레포에 복사하지 않음**) | 개인 에이전트 작업 폴더의 도구 호출 전 훅 스크립트 47개와 그 테스트. 운영하며 얻은 「어떤 호출이 위험했나」 경험이 규칙 설계의 출발점일 뿐, 코드·테스트는 재사용하지 않았다. |
| 신규(이 레포 전부, 2026-10-20 작성) | `gatekeep/` 전 계층, 테스트, 데이터 구축 스크립트, 실측 실행기, SPEC |
| 제3자(비교·데이터용, 무수정) | 아래 「출처」 |

## 출처·라이선스
- AgentDojo (MIT) — `data/raw/agentdojo/*.py` (사용자 과제·주입 과제 정의, ast로 읽기만 하고 실행하지 않음), 공격 문구 템플릿 `important_instructions`
- deepset/prompt-injections (Apache-2.0) — `data/raw/deepset_all.json`
- Rebuff 휴리스틱 (Apache-2.0, protectai/rebuff) — `gatekeep/adapters/baselines/third_party/`
- Vigil-LLM YARA 규칙 (Apache-2.0, deadbits/vigil-llm) — `data/third_party/*.yar`
- 자세한 줄: `data/third_party/NOTICE.md`

## 한계 (실측표 5절에 같은 내용)
- 출처 추적(사용자 요청·허용 도구·신뢰할 수 없는 글)을 에이전트 런타임이 넘겨준다고 가정한다.
- 허용된 수신자에게 가는 **본문 변조**, 한도 안 금액 변조, 행동 없는 오정보는 막지 못한다(자체 시나리오 `known-limit`로 일부러 넣어 놓쳤다고 표에 적음).
- 수신자·금액을 문서에서 가져오는 정당한 작업: 사용자가 그 문서를 가리켰다고 런타임이 알려 주면 CONFIRM(사용자 1회 확인), 모르면 BLOCK. 146건 입력에는 이 표시가 없어 오탐 5건은 그대로다. CONFIRM은 고지서가 진짜인지 보증하지 않는다.
- 허용 도구 목록(R1)이 정확하다는 가정: 벤치는 AgentDojo 정답 호출에서 뽑은 오라클을 쓴다. 정상 과제의 도구 응답은 채움 문장이다.
- 레드팀 우회 입력(`data/redteam_cases.jsonl`)은 우회가 알려진 뒤 만든 회귀 시험이다. 일반 차단율 근거가 아니다.
- 도구 이름 추론은 보조 장치다(`data/city_pack.json`에 도구를 명시 등록하면 추론을 쓰지 않는다).
- 딥러닝 분류기와의 비교는 아직 없다(`scripts/classroom_deberta.py` = 강의실 PC용 실행카드, 미실행).
