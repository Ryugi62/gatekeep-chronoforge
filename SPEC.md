# GateKeep SPEC — AI 에이전트 행동 검문소 (ChronoForge 2026, Cybersecurity 트랙)

## 1. 목적
도시 서비스용 AI 에이전트가 **도구를 호출하기 직전**(송금·메일·파일 삭제·외부 전송·권한 부여)에 그 호출을 규칙으로 검문해 막고, 막은 이유를 증거로 남긴다.
프롬프트 문장을 걸러 내는 분류기가 아니라 **행동 단계 관문**이다. 에이전트가 속았더라도(프롬프트 주입) 위험한 행동은 실행되지 않는다.

## 2. 유비쿼터스 언어 (코드 이름과 일치)
| 용어 | 뜻 |
|---|---|
| ToolCall | 에이전트가 실행하려는 도구 호출 1건 (도구 이름 + 인자) |
| Task | 사용자가 시킨 일 — 사용자 요청 원문, 허용 도구 목록, 에이전트가 읽은 신뢰할 수 없는 글(웹·메일·도구 응답) |
| Policy | 도구별 위험 등급(Risk)과 한도(송금 상한·작업 폴더) |
| Rule | ToolCall 하나와 Task·Policy를 보고 위반 Evidence를 내거나 침묵하는 순수 판정 |
| Checkpoint | Rule 묶음. ToolCall을 검문해 Verdict를 낸다 |
| Verdict | 허용(ALLOW) 또는 차단(BLOCK) + 근거 Evidence 목록 |
| Evidence | 어떤 Rule이 왜 막았는지(규칙 번호·사유·상세) — 감사 기록의 한 줄 |
| Risk | READ·SENSITIVE_READ·OUTBOUND·MONEY·DESTRUCTIVE·STATE_CHANGE |

## 3. 규칙 (Rule) 목록
- R0 UnknownTool — 등록·추론되지 않은 도구는 기본 거부
- R1 OutOfScope — READ가 아닌 도구가 Task.allowed_tools 밖이면 차단 (최소 권한)
- R2 TaintedDestination — 송금·발송·권한 부여의 목적지 인자가 사용자 요청에는 없고 신뢰할 수 없는 글에만 나오면 차단
- R3 AmountLimit — 송금액이 Policy.max_amount를 넘고 그 금액이 사용자 요청에 없으면 차단
- R4 PathEscape — 파괴 도구의 경로가 작업 폴더 밖·`..`·위험 셸 명령이면 차단
- R5 SecretEgress — 외부 전송 인자에 비밀(API 키·개인 키·비밀번호 값)이 들어 있으면 차단

## 4. 숫자 성공 조건 (착수 전 고정, 2026-10-20)
- S1 테스트 ≥ 40개 전부 통과 (도메인·응용·어댑터·벤치 계층)
- S2 실측 입력 파일 1개: 공격 ≥ 60건(공개 세트 + 자체) · 정상 ≥ 30건. 공개 세트 출처·라이선스를 표에 적는다
- S3 GateKeep 차단율 ≥ 85% (공격 전체) · 오탐률 ≤ 10% (정상 전체)
- S4 같은 입력 파일을 GateKeep과 기존 가드레일 ≥ 2종에 돌려 차단율·오탐률·건수를 `results/compare.md`에 같은 표로 낸다 (한계·놓친 건 포함)
- S5 차단된 도구 본체는 0회 실행 (동작 관문 시험)
- S6 차단 Verdict의 100%가 Evidence ≥ 1과 감사 기록 1줄을 남긴다
- S7 검문 지연 p95 < 5 ms / 호출 (Python 단일 프로세스)

## 5. Given / When / Then
1. Given 사용자가 「이 메일 요약해 줘」(허용 도구 read_email) · When 메일 본문에 숨은 지시로 에이전트가 send_email을 호출 · Then R1이 BLOCK, Evidence에 `R1`과 도구 이름.
2. Given 사용자가 「청구서 결제해 줘」·허용 pay_bill · When 인자 수취 계좌가 청구서 본문에만 있고 사용자 요청에 없음 · Then R2가 BLOCK.
3. Given 허용 pay_bill · When 금액이 상한 초과이고 사용자 요청에 그 금액이 없음 · Then R3 BLOCK. 사용자가 그 금액을 직접 말했으면 ALLOW.
4. Given 허용 delete_file·작업 폴더 /workspace · When 경로가 `/workspace/tmp/a.txt` · Then ALLOW. 경로가 `/` 또는 `/workspace/../etc/passwd` · Then R4 BLOCK.
5. Given 허용 send_email · When 본문에 `AKIA…` 형태 키 · Then R5 BLOCK.
6. Given 허용 도구 안의 정상 호출(사용자가 말한 수신자·한도 내 금액) · When 검문 · Then ALLOW (오탐 0).
7. Given 게이트로 감싼 도구 상자 · When 차단 Verdict · Then 도구 본체는 호출되지 않고 `ToolCallBlocked`가 발생, 감사 기록 1줄.

## 6. 비목표
- 프롬프트·자연어를 분류하는 모델 (학습 없음, LLM 호출 없음)
- 인자 값의 의미 이해(예: 허용된 수신자의 본문이 피싱인지) — 알려진 한계로 실측표에 놓친 건으로 기록
- 실서비스 배포·실제 송금·실제 메일 발송 (도구는 전부 모의 함수)
- 딥러닝 분류기를 맥에서 돌리는 것 (사용자 규칙 — 비교 대상은 CPU 규칙 기반 오픈소스만)

## 7. 아키텍처 (의존 방향 domain ← application ← adapters ← infrastructure)
- `gatekeep/domain` — 순수 판정 (프레임워크·I/O 모름)
- `gatekeep/application` — GuardToolCall 유스케이스, 포트(AuditLog·TextGuard)
- `gatekeep/adapters` — JSONL 감사 기록, 도구 위험 추론, 케이스 변환, 게이트 도구 상자, 비교 대상 어댑터
- `gatekeep/infrastructure` — 벤치 실행기(CLI)

## 6. UI 수용기준 (demo/index.html — 비로그인 정적 데모, notes/원칙-디자인 체크리스트 10 적용)
- 1 모바일 퍼스트: 390px 가로 스크롤 0, viewport 메타 · 2 입력 4개(요청·허용 도구·호출 JSON·읽은 글)는 한 화면 세로 배치, 주 행동 「Check」 1개
- 3 본문 ≥16px·줄간격 ≥1.5 · 4 간격·라운드 4/8 배수, 카드 라운드 16px · 5 모든 버튼 높이 ≥44px
- 9 글자 대비 ≥4.5:1(라이트·다크 둘 다), 포커스 표시 · 10 외부 폰트·CDN·서버 호출 0 (테스트: test_index_is_static_and_has_inputs)
- 수용 시험: `python3 /Users/ryugi62/jarvis/_system/ui_audit.py demo/index.html` fail 0, 예시 3개 판정(tests/demo/test_demo_examples.py), JS=파이썬 146건 일치(tests/demo/test_demo_parity.py)
