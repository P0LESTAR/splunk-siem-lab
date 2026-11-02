# S3 트리아지 자동화 — Webhook 수신과 근거 기반 분석

## 범위와 검증 상태

- Python 표준 라이브러리만 사용한다. 추가 패키지는 필요 없다.
- POST `/webhook/splunk`의 JSON을 파일로 저장한 뒤 HTTP 200을 반환한다.
- `sid`(비어 있지 않은 문자열), `result`(객체)를 요구한다. 최대 본문 크기는 65536 바이트이다.
- 수신 주소는 IPv4 `127.0.0.1`로 고정한다. 외부 공개용 서버가 아니다.
- `triage_analyzer.py`는 저장된 알림 결과 1건을 기준으로 관련 Sysmon 로그를 REST로 조회하고 Markdown 요약과 증거 JSON을 생성한다. `--watch`는 inbox를 반복 확인하고 실패한 파일을 다음 스캔에서 다시 시도한다. 서비스 등록과 자동 대응은 구현하지 않았다.
- 호스트 Windows Python 3.14.9에서 실제 loopback HTTP 요청을 보내 정상 저장 및 비정상 요청 거부 테스트를 통과했다. 테스트 입력은 모두 `TEST_ONLY` 합성 데이터이며 실제 Splunk Alert가 아니다.
- 사용자가 제공한 Ubuntu VM 출력으로 합성 요청 저장, 실제 예약 Alert 수신, REST 단건 분석, 새 GUID의 `--watch` 자동 처리와 보고서 생성을 확인했다. 사용자 제공 증거를 확인한 것이며 에이전트가 VM에 직접 접속하거나 원본 증거 파일을 호스트로 복사한 것은 아니다.

## 테스트

저장소 루트에서:

```bash
python -m unittest discover -s automation/tests -v
```

Ubuntu에서 실행할 때에는 `python` 대신 `python3`를 사용한다.

## VM 배포 (사용자 실행)

Windows PowerShell에서 기존 SSH 별칭 `splunk`를 사용한다:

```powershell
scp "C:\Users\itsme\Desktop\splunk-siem-lab\automation\triage_receiver.py" splunk:triage_receiver.py
```

Splunk Ubuntu VM의 일반 사용자 터미널에서:

```bash
python3 ~/triage_receiver.py
```

기본 출력 위치는 실행 사용자 홈의 `~/splunk-triage/inbox/`이다. `/opt/splunk` 소유권을 바꾸거나 root로 실행할 필요가 없다. 터미널을 닫으면 수신기도 종료된다. 중지는 Ctrl+C이며 상시 실행은 후속 단계로 분리한다.

## 합성 요청으로 수신기 자체 확인

수신기를 켜둔 상태로 같은 VM의 다른 터미널에서:

```bash
curl --noproxy '*' --max-time 5 -i \
  -X POST http://127.0.0.1:18080/webhook/splunk \
  -H 'Content-Type: application/json' \
  --data '{"sid":"TEST_ONLY_manual","search_name":"TEST_ONLY_receiver_check","result":{"host":"TEST_ONLY_host","ProcessGuid":"TEST_ONLY_guid"}}'
```

기대 결과는 HTTP 200과 `{"status": "saved"}` 응답, 수신기 콘솔의 `saved: <파일명>.json` 출력이다. 실제 수신 여부는 VM에서 확인해야 한다.

파일 구조는 `received_at`(UTC 수신 시각), `payload`(수신한 Webhook JSON)이다. 파일 이름은 서버에서 생성하며 요청의 SID나 경로를 파일 이름으로 사용하지 않는다. 원본 데이터는 사용자·호스트·명령줄 등 민감한 내용을 포함할 수 있으므로 저장소에 복사하거나 공개하지 않는다.

## 다음 단계: 실제 Splunk Alert 연결

1. 수신기를 실행한 상태로 유지한다.
2. Splunk Enterprise에서는 `/opt/splunk/etc/system/local/alert_actions.conf`의 기존 내용을 보존하면서 아래 설정을 병합한다. `[webhook]`이 이미 있으면 그 안에 추가하고, 기존 allowlist 항목도 유지한다. `system/default`는 수정하지 않는다. Cloud용 Web UI 메뉴가 Enterprise에도 있다고 가정하지 않는다.

   ```ini
   [webhook]
   enable_allowlist = true
   allowlist.triage_local = ^http://127\.0\.0\.1:18080/webhook/splunk$
   ```

   `enable_allowlist`는 허용 목록 검사를 켜고, 정규식은 이 주소만 정확히 허용한다. 비어 있는 허용 목록으로 검사만 켜지 않는다. 변경 후 `sudo -u splunk /opt/splunk/bin/splunk restart`로 적용한다. 재시작 동안 검색과 웹 접속이 잠시 중단되며, 별도 터미널의 Python 수신기는 켜둔다.
3. 기존 S3 Alert의 Webhook 작업에 동일 주소를 입력한다. `트리거된 경고에 추가` 액션은 유지한다.
4. 새로 발생한 실제 탐지 결과의 SID와 ProcessGuid를 저장된 JSON과 대조한다.
5. 수신기는 중복 요청도 각각 저장한다. 동일 이벤트가 반복 발생하는 문제는 경고 억제 설정 및 후속 분석기의 이벤트 중복 방지로 다룬다.

Webhook에는 첫 결과 행만 포함되므로 전체 결과 처리는 후속 단계에서 신뢰하는 Splunk REST 주소로 SID 조회를 수행한다. 수신된 `results_link`를 인증정보와 함께 자동으로 조회하지 않는다. 원본 Webhook 저장만으로 트리아지 완성을 주장하지 않는다.

## 2단계: REST 로그 조회와 1차 요약

### 분석 범위

- 입력은 이 Webhook의 `result` 1건이다. 현재 Alert는 per-result 모드로 운영한다. 같은 SID의 다른 결과 전체를 처리하는 배치 분석기는 아니다.
- `host + ProcessGuid`를 중심으로 Sysmon EID 1(해당 프로세스와 직접 부모), EID 10(해당 프로세스의 LSASS 접근), EID 3(해당 프로세스 연결)을 조회한다.
- 원본 이벤트 이전 10분~이후 2분을 조회한다. 즉시 단건 실행은 현재 시각까지만 조회하고 미완료 관찰 구간을 표시한다.
- watch 모드는 이벤트 이후 3분이 지난 뒤 처리한다. 이는 후속 2분과 수집 여유 1분을 기다리는 랩 기본값이지 지연 로그를 모두 보장하는 값은 아니다.
- 부모가 검색 구간 이전에 생성되면 부모 생성 이벤트는 누락될 수 있다. 전체 조상 트리, 인증 이벤트 연계, 파일 서명 확인은 미구현이다.
- 기본 최대 1000건을 페이지 조회하며, 제한이나 불완전한 반환은 요약에 명시한다.
- LSASS 접근과 자격 증명 추출 성공은 구분한다. 정상 관리 작업 여부도 승인 정보 없이 확정하지 않는다.
- `host + ProcessGuid` 기반으로 완료된 프로세스 분석을 중복 처리하지 않는다. 같은 프로세스의 후속 접근을 각각 새 경보로 처리하려는 용도가 아니다. 필요하면 `--refresh`로 재조회한다.
- 결과에는 토큰을 저장하지 않는다. 다만 명령줄·계정·원본 Webhook 링크 같은 민감한 운영 데이터는 포함되므로 공개하지 않는다.

### API 토큰 준비 — 토큰을 채팅에 붙이지 않는다

1. 관리자 계정으로 Settings > Roles에서 전용 역할을 만들고 `search` capability와 `sysmon` 인덱스 검색 권한을 부여한다. 불필요한 관리·쓰기 권한을 추가하지 않는다.
2. Settings > Users에서 해당 역할을 가진 전용 사용자를 만든다.
3. Settings > Tokens에서 토큰 인증을 활성화하고 New Token으로 그 사용자에 대한 만료 기간이 짧은 토큰을 만든다. Audience는 `splunk-triage-lab`처럼 용도를 기록한다. 토큰 인증에는 TLS와 정상 KV Store가 필요하다.
4. 분석기를 실행하면 숨김 입력 프롬프트가 나온다. 토큰은 이 프롬프트에만 직접 입력한다. 토큰을 명령 인자·저장소·스크린샷·채팅에 넣지 않는다.
5. 자동 실행 환경에는 `SPLUNK_TOKEN` 환경변수도 지원하지만, 이번 수동 검증에는 숨김 프롬프트를 사용한다. 테스트 종료 후 불필요한 토큰은 폐기한다.

토큰 권한은 발급 대상 사용자의 권한을 따른다. 사용자 이름이 `user`인 Ubuntu 계정과 Splunk 웹의 사용자 계정은 별개다. 이 분석기는 자체 보강 검색을 생성하므로 admin 소유의 원래 검색 작업을 읽을 권한은 요구하지 않는다.

### 배포와 단건 검증

Windows PowerShell:

```powershell
scp "C:\Users\itsme\Desktop\splunk-siem-lab\automation\triage_analyzer.py" splunk:triage_analyzer.py
```

Splunk VM에서, 이미 수신한 실제 JSON을 입력한다:

```bash
python3 ~/triage_analyzer.py \
  --input ~/splunk-triage/inbox/20261101T105402649619Z_62983fc944e740dfbf710ca2ffb8418d.json \
  --insecure-local
```

기본 REST 주소는 `https://127.0.0.1:8089`이다. `--insecure-local`은 랩의 self-signed 인증서 검사를 명시적으로 생략하며 127.0.0.1에만 허용한다. 암호화는 유지되지만 서버 인증은 생략되므로 운영 환경에서는 올바른 인증서와 `--ca-file`을 사용한다. HTTP나 다른 호스트의 인증서 검사 생략은 CLI에서 허용하지 않는다. URL 리다이렉트와 환경 프록시는 사용하지 않는다.

실제 성공은 `status=created` 출력과 생성된 두 파일을 확인해야 한다:

```text
~/splunk-triage/reports/<host와 GUID 기반 식별자>/
├─ report.md
├─ evidence.json
└─ .complete
```

401은 토큰·만료·토큰 인증 설정을, 403은 검색 권한을 확인한다. 0건이면 원본 이벤트 시각·host·필드명·인덱스 검색 권한을 확인한다. HTTP 성공이나 0건 자체를 탐지 성공/행위 없음의 증거로 해석하지 않는다. 보고서의 검색 링크에는 절대 시간과 SPL이 들어 있어 작업 SID가 만료돼도 조건을 다시 조회할 수 있다.

### 계속 처리하기

단건 결과를 실제 데이터로 확인한 다음, 단건 실행을 종료하고 별도 터미널에서:

```bash
python3 ~/triage_analyzer.py \
  --inbox ~/splunk-triage/inbox \
  --watch --insecure-local
```

수신기와 분석기를 각각 켜둔다. 분석기는 한 인스턴스만 실행한다. 기본 스캔 간격은 30초이며 `.complete`가 있는 같은 프로세스는 재검색하지 않는다. 테스트 수신용 fixture는 건너뛴다. 종료는 Ctrl+C다. 실패는 완료로 표시하지 않아 후속 스캔에서 재시도하지만, 재시도 횟수 제한·지수 백오프·실패 격리함은 아직 없다. 계속 오류가 나면 중지하고 설정을 수정한다.

새 로그를 반영하려면 해당 JSON으로 단건 실행하면서 `--refresh`를 추가한다. refresh와 watch는 함께 사용하지 않는다.

### 검증의 경계

호스트 테스트는 실제 HTTP 요청을 보내는 **합성 Splunk REST 계약 테스트**다. 정상 조회·페이지 처리·보고서 생성·GUID 기준 중복 억제·지연 관찰·입력 검증·토큰 리다이렉트 차단·인증 오류·미완료/강제 종료 검색・REST 시각 표기를 검증한다. 사용자 제공 실제 VM 보고서와 `created` 관측으로 REST 단건 분석뿐 아니라 새 GUID의 `--watch` 자동 처리까지 확인했다. 정상 작업 자동 분류, 서비스 등록, 지속 운영 신뢰성 시험은 미완료다.

### 실제 새 실행 검증 증거 (사용자 제공)

- 호스트: `win10-vic`
- ProcessGuid: `{e29e4255-3441-6ae7-450b-000000000600}` — 이전 단건 실행과 다른 GUID.
- 사용자 관측: 분석기 터미널에 `created`가 출력됐고 새 보고서가 생성됐다.
- VM 보고서: `/home/user/splunk-triage/reports/d7e678fbd93b605ea9b33597f891d337f0191b9c3584995353686ad2c7fa4f68/report.md`
- 타임라인(KST): CMD 생성 `21:44:37.106` → mimi 생성 `21:44:49.719` → LSASS 접근 `21:44:58.934`.
- 접근 권한: `0x1010`. 관측된 접근과 자격 증명 추출 성공을 구분한다.
- 실제 반환 이벤트 3건, 검색 결과 3건. 보강 검색 SID: `1793537283.418`.
- 원본 `report.md`/`evidence.json`은 VM에 있으며 이 저장소에는 아직 복사하지 않았다. 로그 출력으로 확인된 결과와 저장소에 보관된 증거 파일을 혼동하지 않는다.

공식 문서:
- https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-tutorials/10.6/rest-api-tutorials/creating-searches-using-the-rest-api
- https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.6/authenticate-into-the-splunk-platform-with-tokens/create-authentication-tokens
