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
| win-vic | Windows | 10.10.10.20 | VMnet2 인터페이스 = Ethernet0 |
| linux-victim | Ubuntu | 10.10.10.21 | |
| kali | Kali Linux | 10.10.10.100 | 공격자 |

- Ubuntu VM: `ens33` = NAT(DHCP), `eth0` = VMnet2 고정 IP, 게이트웨이 없음.
- VMware 쪽 VM 폴더/vmx 이름은 예전 그대로다: win-vic = `win-victim\win-victim.vmx`, linux-victim = `Ubuntu 64-bit\Ubuntu 64-bit.vmx` (`C:\Users\itsme\Documents\Virtual Machines\` 아래).

## SSH
접속 정보는 `~/.ssh/config`의 별칭으로 관리한다(이 파일엔 별칭만 기록).

사용자는 전부 `user`, 키는 `~/.ssh/id_ed25519`. 예전 별칭 `win-victim`, `lnx-victim`도 호환용으로 남아 있다.

| 별칭 | 호스트명 | VMnet2 / NAT IP | SSH 상태 |
|---|---|---|---|
| `splunk` | splunk | 10.10.10.10 / 192.168.25.128 | 키 인증 OK |
| `win-vic` | win-vic | 10.10.10.20 | SSH 사용 안 함(결정) — 콘솔에서 작업 |
| `linux-victim` | linux-victim | 10.10.10.21 / 192.168.25.133 | 키 인증 OK |
| `kali` | kali | 10.10.10.100 / 192.168.25.134 | 키 인증 OK (eth1 = VMnet2, NetworkManager 연결 `labnet`) |

- sudo: `splunk`, `kali`는 NOPASSWD(`/etc/sudoers.d/90-lab-user`) → 에이전트가 `sudo -n`으로 직접 실행. `linux-victim`은 비밀번호 필요(권한 상승 시나리오 보존을 위해 의도적으로 유지) → sudo 작업은 사용자에게 명령을 안내한다.

- Kali는 netplan이 아니라 NetworkManager 사용. eth0 = NAT(DHCP), eth1 = VMnet2 고정, `ipv4.never-default yes`.

예: `ssh splunk 'sudo -u splunk /opt/splunk/bin/splunk status'`

- 호스트(10.10.10.1)에서 들어오는 SSH는 관리용 세션이다. Splunk에서 탐지 룰을 만들 때 공격 트래픽과 구분하도록 태그를 붙이거나 제외한다.

## Splunk 주의사항
- root 실행 거부됨 → `/opt/splunk`를 `splunk` 사용자 소유로 chown, `sudo -u splunk`로 실행.

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
- Windows 실습 계획: S0 준비(허용 규칙, 5156/5157·4104 수신 확인, 스냅샷) → S1 포트 스캔 T1046 → S2 SMB 브루트포스 T1110 → S3 LSASS 접근 T1003.001 → S4 PowerShell -enc/Run 키 T1059.001·T1547.001 → S5 Defender 무력화 T1562.001 → 대시보드·튜닝·보고서. Alert 캡처는 Trial 만료(약 12/7) 전에.
- [ ] 공격 시뮬레이션 및 탐지 룰 작성 (저장된 검색 아직 없음)
- [ ] 포트폴리오 문서화

스냅샷: splunk `splunk 설치`, linux-victim `splunk uf 초기셋팅`, kali `Snapshot 1`. win-vic VM은 암호화되어 있어 vmrun으로 조회 불가(콘솔에서 확인).
