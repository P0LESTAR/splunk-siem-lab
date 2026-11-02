# Splunk SIEM Homelab

블루팀 직무 지원용 포트폴리오 프로젝트(약 2개월). Splunk 기반 SIEM 랩을 구축하고 공격 시뮬레이션 → 탐지 → 대응까지 문서화한다.

## 작업 규칙
- 답변은 한국어로.
- 사용자는 레드팀 경험은 많고 블루팀/VMware/Linux 서버 세팅은 초보. 공격 기법 설명은 생략 가능, 인프라·SIEM 쪽은 단계별로.
- GUI 방법이 있으면 CLI와 함께 제시한다.
- 비밀번호·키·토큰은 이 파일이나 저장소에 절대 기록하지 않는다.

## 호스트
- Windows 11, VMware Workstation: `C:\Program Files (x86)\VMware\VMware Workstation`
- 관리자 권한 vmnetcfg는 자동화 도구로 읽을 수 없음(UIPI) → `vnetlib64.exe` CLI를 RunAs로 사용.

## 네트워크
| VMnet | 종류 | 대역 | 비고 |
|---|---|---|---|
| VMnet2 | Host-only | 10.10.10.0/24 | 랩 내부망, DHCP 없음, 호스트 10.10.10.1 |
| VMnet8 | NAT | 192.168.25.0/24 | 인터넷용, DHCP |
| VMnet0/1 | — | — | 사용 안 함 |

## VM
이름 = OS 호스트명 = Splunk `host` 필드 값. 문서·SPL·lookup·대시보드에서는 이 이름만 쓴다.

| 이름 | OS | VMnet2 IP | 비고 |
|---|---|---|---|
| splunk | Ubuntu Server | 10.10.10.10 | Splunk Enterprise |
| win-vic | Windows 11 | 10.10.10.20 | VMnet2 인터페이스 = Ethernet0 |
| win10-vic | Windows 10 (영문판) | 10.10.10.22 | 레거시(지원 종료) 엔드포인트 피해자. VMnet2 인터페이스 이름 = `LAB`, NAT = `NAT` |
| linux-victim | Ubuntu | 10.10.10.21 | |
| kali | Kali Linux | 10.10.10.100 | 공격자 |

- Ubuntu VM: `ens33` = NAT(DHCP), `eth0` = VMnet2 고정 IP, 게이트웨이 없음.
- win10-vic: 어댑터 이름을 직접 바꿔 둠. `LAB` = VMnet2 고정 10.10.10.22/24(게이트웨이·DNS 없음, 프로필 Private), `NAT` = DHCP. VMware 어댑터 순서와 Windows `EthernetN` 번호는 일치하지 않으니 이름이 아니라 IP(169.254.x = VMnet2, 192.168.25.x = NAT)나 MAC으로 구분한다.
- win10-vic는 영문판이다 → 메뉴 이름은 영어로 안내. 감사 정책은 언어와 무관한 GUID 방식으로 설정한다.
- win10-vic와 win-vic(Win11)을 병행 운영할지, win10-vic로 대체할지는 아직 결정하지 않았다.
- VMware 쪽 VM 폴더/vmx 이름은 예전 그대로다: win-vic = `win-victim\win-victim.vmx`, linux-victim = `Ubuntu 64-bit\Ubuntu 64-bit.vmx` (`C:\Users\itsme\Documents\Virtual Machines\` 아래).

## SSH
접속 정보는 `~/.ssh/config`의 별칭으로 관리한다(이 파일엔 별칭만 기록).

사용자는 전부 `user`, 키는 `~/.ssh/id_ed25519`. 예전 별칭 `win-victim`, `lnx-victim`도 호환용으로 남아 있다.

| 별칭 | 호스트명 | VMnet2 / NAT IP | SSH 상태 |
|---|---|---|---|
| `splunk` | splunk | 10.10.10.10 / 192.168.25.128 | 키 인증 OK |
| `win-vic` | win-vic | 10.10.10.20 | SSH 사용 안 함(결정) — 콘솔에서 작업 |
| — | win10-vic | 10.10.10.22 / DHCP | SSH 미설정 — 콘솔에서 작업 |
| `linux-victim` | linux-victim | 10.10.10.21 / 192.168.25.133 | 키 인증 OK |
| `kali` | kali | 10.10.10.100 / 192.168.25.134 | 키 인증 OK (eth1 = VMnet2, NetworkManager 연결 `labnet`) |

- sudo: `splunk`, `kali`는 NOPASSWD(`/etc/sudoers.d/90-lab-user`) → 에이전트가 `sudo -n`으로 직접 실행. `linux-victim`은 비밀번호 필요(권한 상승 시나리오 보존을 위해 의도적으로 유지) → sudo 작업은 사용자에게 명령을 안내한다.

- Kali는 netplan이 아니라 NetworkManager 사용. eth0 = NAT(DHCP), eth1 = VMnet2 고정, `ipv4.never-default yes`.

예: `ssh splunk 'sudo -u splunk /opt/splunk/bin/splunk status'`

- 호스트(10.10.10.1)에서 들어오는 SSH는 관리용 세션이다. Splunk에서 탐지 룰을 만들 때 공격 트래픽과 구분하도록 태그를 붙이거나 제외한다.

## Splunk 주의사항
- root 실행 거부됨 → `/opt/splunk`를 `splunk` 사용자 소유로 chown, `sudo -u splunk`로 실행.

## Windows 피해자 주의사항
- 원격 Impacket(SMB/WMI) 접속 시 ACCESS_DENIED(0xc0000022) 발생 시: 로컬 관리자 원격 제한 비활성화 `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f` (재부팅 불필요)
- UF는 설치 시점의 컴퓨터 이름을 `host` 값으로 저장한다 → 호스트명을 먼저 확정하고 UF를 설치한다.
- Windows 10 기본 감사 정책은 4688(프로세스 생성)을 남기지 않는다. 파이프라인은 정상인데 이벤트가 없으면 원본에서 `auditpol` / `Get-WinEvent`부터 확인한다.
- Windows PowerShell 5.1에서 `wget`·`curl`은 `Invoke-WebRequest` 별칭 → 복사한 `wget -O ...`는 실패. `curl.exe -L -o` 사용.
- 새로 설치한 VM 브라우저로 splunk.com 다운로드 페이지에 접속하면 Akamai "Access Denied"가 뜰 수 있음 → 호스트에서 받거나 `download.splunk.com` 직접 링크 사용.
- UF 설치 마법사의 이벤트 로그 체크박스는 비워 둔다(체크하면 `main` 인덱스로 감). inputs.conf에서 인덱스를 지정한다.
- 특정 채널만 0건이면 UF `var\log\splunk\splunkd.log`에서 채널 이름으로 검색한다.
  - `Failed to find Event Log with channel name` = UF가 시작할 때 채널이 없었음(Sysmon을 UF보다 나중에 설치) → UF 재시작.
  - `unable to subscribe ... errorCode=5` = 접근 거부. 최근 UF는 기본으로 가상 계정 `NT SERVICE\SplunkForwarder`로 실행되며, Security는 읽어도 Sysmon 채널은 못 읽을 수 있다. → 해당 계정을 Event Log Readers에 추가하고 UF 재시작(최소 권한), 안 되면 LocalSystem으로 변경.

## 진행 상황
- [x] VMware 가상 네트워크 구성
- [x] splunk / linux-victim VM 기본 세팅
- [x] Splunk 10.6 설치, 수신 9997, 인덱스 `wineventlog`/`sysmon`/`linux`, TA(windows/sysmon/nix) + CIM 설치 (라이선스: Enterprise Trial)
- [x] 로그 수집: win-vic(UF + Sysmon → `wineventlog`/`sysmon`, sourcetype `XmlWinEventLog`), linux-victim(UF → `linux`: audit.log, auth.log, syslog)
- [x] GitHub 저장소: https://github.com/P0LESTAR/splunk-siem-lab (private, `main`). `gh`는 `%LOCALAPPDATA%\ghcli\bin`(PATH 미등록)
- 라이선스: Enterprise Trial(2026-10-08 시작, 약 12/7 만료) → 이후 Free 전환 예정. Free는 알림/예약 검색 없음 → 알림 동작 캡처는 만료 전에 완료
- [x] 가시성 점검(2026-10-14, 24h): 5개 소스 모두 수신, 일 사용량 약 112MB/500MB. linux:audit 99.7MB — apt/dpkg 작업 중 `usr_writes` 키 폭증 + UF `splunkd`가 audit.log를 읽을 때 `auditlog` 키가 다시 기록하는 루프(Linux 단계에서 정리). PowerShell/Operational은 10/13 14:20 이후 이벤트 없음(수집 재확인 필요)
- 순서: **Windows(win-vic) 시나리오 먼저**, Linux는 나중에. 그동안 linux-victim VM은 꺼둠 → `linux` 인덱스 무수신은 정상.
- [x] win-vic: WFP 감사 활성화(2026-10-14) — 필터링 플랫폼 연결 `{0CCE9226}` 성공+실패(5156/5157), 패킷 삭제 `{0CCE9225}` 실패(5152). 방화벽 3개 프로필 ON. 허용 규칙(445/135/3389/5985 ← 10.10.10.0/24)·Splunk 수신 확인은 미검증
- Windows 실습 계획: S0 준비 → S1 포트 스캔 → S2 SMB 브루트포스 → [x] S3 LSASS 접근 T1003.001 → [x] S4 PowerShell -enc/Run 키 → [x] S5 Defender 무력화·감사 로그 삭제 → 대시보드·튜닝·보고서. Alert 캡처는 Trial 만료(약 12/7) 전에.
- win10-vic 구축(2026-10-20):
  - [x] Windows 10 영문판 설치, 로컬 계정
  - [x] VMnet2 고정 IP 10.10.10.22, splunk(10.10.10.10) ping·9997 연결 확인
  - [x] UF 설치(Local System, 수신 10.10.10.10:9997), inputs.conf는 win-vic와 같은 채널·인덱스 구성. `_internal`·`wineventlog`에서 `host=win10-vic` 수신 확인
  - [x] 감사 정책(GUID 922B, 9215, 9216, 921B, 9217, 923F, 9235, 9237, 9224, 9227, 9211) + 명령줄 기록 + ScriptBlockLogging → `whoami` 4688 Splunk 수신 확인
  - WFP 감사(9226/9225)는 이벤트량 때문에 일부러 켜지 않음 → 네트워크 탐지 단계에서 켤 예정
  - [ ] 방화벽 허용 규칙(`Lab-Inbound` 445/135/3389/5985, `Lab-ICMP`) 적용 여부 미확인
  - [x] Defender 끄기(변조 보호 → 실시간 보호 순서). 실시간 보호는 재부팅 후 다시 켜질 수 있음 → 공격 실습 전 확인
  - [x] Sysmon(SwiftOnSecurity, `C:\Tools\Sysmon`) 설치 → UF 재시작 → `sysmon` 인덱스 수신 확인. 처음엔 UF 서비스 계정 권한 문제로 0건(아래 주의사항 참고). 적용한 해결 방법(Event Log Readers 추가 / LocalSystem 변경)은 기록 필요
  - [x] Sysmon EID 10(ProcessAccess) 활성화: SwiftOnSecurity 기본값은 include 규칙이 비어 있어 아무것도 기록하지 않음 → `TargetImage end with \lsass.exe` 추가 후 `Sysmon64.exe -c`로 적용(원본은 `sysmonconfig.xml.bak`). Splunk 수신 확인. 정상 기준선 정리와 이벤트량 튜닝은 아직
  - [x] NAT 연결 해제, 스냅샷(`baseline-logging-ok`)
- [x] S3 실습 완료: Mimikatz 덤프 탐지 및 Alert 구축
- [x] S4 실습 완료: PowerShell -enc/Run 키 공격 탐지 및 쿼리 도출 (2026-10-22)
- [x] S5 실습 완료: Defender 무력화(T1562.001) 차단·성공 비교 및 Security 감사 로그 삭제(T1070.001) 탐지, `실습보고서5.md` 작성 (2026-10-30)
- [x] **알림 트리아지 자동화(Python) — S3 MVP**
  - 사용자 선택에 따라 S3 하나를 먼저 완성. 사용자 제공 새 실행 보고서와 분석기 `created` 관측으로 Alert → Webhook 수신 → REST 관련 로그 조회 → Markdown 요약 자동 생성의 라이브 E2E를 확인했다. 에이전트가 VM에 직접 접속해 확인한 것은 아니다.
  - 코드: `automation/triage_receiver.py`, `automation/triage_analyzer.py`, 실행 문서: `automation/README.md`. Python 표준 라이브러리만 사용.
  - 실제 Alert 조건은 Sysmon EID 1 + `OriginalFileName="mimikatz.exe"`이며, LSASS 접근 결과는 보강 검색의 EID 10으로 확인한다. Alert 제목만 보고 EID 10 탐지라고 설명하지 않는다.
  - 경고는 1분 주기 예약 검색. 사용자가 `host,ProcessGuid` 기준 10분 억제를 적용했다고 확인했고, 제공 scheduler 로그에서도 억제 동작을 확인했다.
  - Webhook: Splunk VM의 `http://127.0.0.1:18080/webhook/splunk`, Enterprise `alert_actions.conf`에 정확한 주소 허용. deprecated `Run a script`는 사용하지 않음.
  - 수신 JSON: `~/splunk-triage/inbox/`. 분석기는 별도 터미널에서 `--watch`로 실행하고 원본 이벤트 이전 10분~이후 2분의 Sysmon EID 1/10/3을 검색한다. watch는 후속 이벤트·수집 여유를 위해 이벤트 이후 3분이 지난 파일부터 처리한다.
  - 출력: `~/splunk-triage/reports/<host와 GUID 기반 식별자>/report.md`, `evidence.json`. 호스트·계정·프로세스·직접 부모·타임라인·조사 권고·조회 링크·분석 한계를 포함. `host + ProcessGuid` 기준 Python 중복 처리 방지.
  - 실제 새 실행 증거: `win10-vic`, GUID `{e29e4255-3441-6ae7-450b-000000000600}`. 사용자 제공 타임라인(KST): 21:44:37.106 CMD 생성 → 21:44:49.719 mimi 생성 → 21:44:58.934 LSASS 접근(`0x1010`). 보강 검색 SID `1793537283.418`.
  - 호스트 계약 테스트 15개 통과. 합성 HTTP 테스트와 사용자 제공 라이브 실행 증거를 구분한다. 미완료·강제 종료 검색은 완료 보고서로 저장하지 않는다.
  - 토큰: 실행 시 숨김 프롬프트 또는 `SPLUNK_TOKEN` 환경변수. 저장소·채팅에 기록 금지. `--insecure-local`은 랩 loopback 인증서 검사 생략이며 운영 환경에서는 CA 검증을 사용한다.
  - [ ] 선택 확장: 정상 승인 작업 분류, 전체 조상 트리·인증 로그 연계, S4/S5 지원, Splunk 인덱스/KV 적재·대시보드, 서비스 등록, 제한된 재시도·백오프, Trial 종료 후 대체 실행 경로. 현재 MVP 완료와 구분한다.

### 다음 세션 시작점 — S3 자동화 증거 정리
1. `git status`로 사용자 변경을 확인하고 기존 변경을 덮어쓰거나 임의 커밋하지 않는다.
2. 사용자가 원하면 `실습보고서3.md`에 자동화 흐름·검증 결과·한계를 추가하고, 실제 Alert/수신/분석기 출력/보고서를 근거로 정리한다. API 토큰과 민감한 원본 로그는 제외한다.
3. VM의 `report.md`와 `evidence.json`은 아직 에이전트가 호스트로 복사하지 않았다. 사용자 제공 출력만 확인된 상태이며, 별도 허가 없이 VM에 접속하지 않는다.
4. 다음 확장은 사용자가 정한다. S3 MVP는 동작 검증됐지만 상시 서비스·S4/S5·정상 작업 자동 분류가 완료됐다고 설명하지 않는다.

- [ ] 포트폴리오 문서화

스냅샷: splunk `splunk 설치`, linux-victim `splunk uf 초기셋팅`, kali `Snapshot 1`. win-vic VM은 암호화되어 있어 vmrun으로 조회 불가(콘솔에서 확인).
