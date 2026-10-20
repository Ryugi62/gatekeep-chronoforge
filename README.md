# GateKeep — AI 에이전트 행동 검문소

도시 서비스용 AI 에이전트가 **도구를 호출하기 직전**(송금·메일·파일 삭제·외부 전송·권한 부여)에 호출을 규칙으로 검문해 막고, 막은 이유(Evidence)를 감사 기록에 남긴다. 프롬프트 문장을 거르는 분류기가 아니라 **행동 단계 관문**이다. 에이전트가 속았더라도 위험한 행동은 실행되지 않는다.

- 스펙: [SPEC.md](SPEC.md) (유비쿼터스 언어 ToolCall·Checkpoint·Rule·Verdict·Evidence, 숫자 성공 조건, Given/When/Then 7개, 비목표)
- 실측표: [results/compare.md](results/compare.md) · 원자료 [results/compare.csv](results/compare.csv)
- 저작 모드: AI 보조(Claude)로 코드를 작성했고 제작자가 검수했다. 제3자 자산은 아래 「출처」에 전부 밝힌다.

## 어떻게 막나 (규칙 6개)
| 규칙 | 막는 것 |
|---|---|
| R0 UnknownTool | 등록·추론되지 않은 도구 (기본 거부) |
| R1 OutOfScope | 사용자 요청 범위 밖의 쓰기·송금·삭제·권한 도구 (최소 권한) |
| R2 TaintedDestination | 수신자·계좌·URL이 사용자 요청에는 없고 신뢰할 수 없는 글(웹·메일·도구 응답)에만 있는 호출 |
| R3 AmountLimit | 상한 초과 금액이 사용자 요청에 없는 송금 |
| R4 PathEscape | 작업 폴더 밖 삭제·`..`·위험 셸 명령 |
| R5 SecretEgress | 외부 전송 인자에 들어간 API 키·개인 키·비밀번호 값 |

```
python3 scripts/demo.py                          # 모의 도구 상자 시연: 정상 호출 통과, 주입된 cc 차단 + 감사 기록
python3 -m pytest -q                             # 테스트
sh scripts/fetch_public.sh                       # (선택) 공개 세트 다시 내려받기
python3 scripts/build_dataset.py                 # data/cases.jsonl 재생성 (시드 고정)
python3 -m gatekeep.infrastructure.bench         # 실측표 재생성 (Rebuff 휴리스틱 때문에 1~2분)
```
Python 3.9 표준 라이브러리만 쓴다(테스트만 pytest). LLM 호출·학습 없음.

## 구조 (의존 방향 domain ← application ← adapters ← infrastructure)
```
gatekeep/domain/          순수 판정: model.py rules.py checkpoint.py      (I/O·프레임워크 모름)
gatekeep/application/     GuardToolCall 유스케이스 + 포트(AuditLog, TextGuard)
gatekeep/adapters/        gate.py(동작 관문) audit_jsonl.py tool_registry.py cases.py baselines/(비교 대상)
gatekeep/infrastructure/  bench.py(실측 실행기) metrics.py
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
- 수신자·금액을 문서에서 가져오는 정당한 작업은 오탐이 난다. 운영에서는 차단 대신 사용자 확인으로 풀어야 한다.
- 딥러닝 분류기와의 비교는 아직 없다(`scripts/classroom_deberta.py` = 강의실 PC용 실행카드, 미실행).
