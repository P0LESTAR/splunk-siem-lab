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
| 이름 | OS | VMnet2 IP | 비고 |
|---|---|---|---|
| splunk | Ubuntu Server | 10.10.10.10 | Splunk Enterprise |
| win-victim | Windows | 10.10.10.20 | VMnet2 인터페이스 = Ethernet0 |
| lnx-victim | Ubuntu | 10.10.10.21 | |
| kali | Kali Linux | 10.10.10.100 | 공격자 |

- Ubuntu VM: `ens33` = NAT(DHCP), `eth0` = VMnet2 고정 IP, 게이트웨이 없음.

## SSH
접속 정보는 `~/.ssh/config`의 별칭으로 관리한다(이 파일엔 별칭만 기록).

사용자는 전부 `user`, 키는 `~/.ssh/id_ed25519`.

| 별칭 | 호스트명 | VMnet2 / NAT IP | SSH 상태 |
|---|---|---|---|
| `splunk` | splunk | 10.10.10.10 / 192.168.25.128 | 키 인증 OK |
| `win-victim` | — | 10.10.10.20 | SSH 사용 안 함(결정) — 콘솔에서 작업 |
| `lnx-victim` | linux-victim | 10.10.10.21 / 192.168.25.133 | 키 인증 OK |
| `kali` | kali | 10.10.10.100 / 192.168.25.134 | 키 인증 OK (eth1 = VMnet2, NetworkManager 연결 `labnet`) |

- sudo: `splunk`, `kali`는 NOPASSWD(`/etc/sudoers.d/90-lab-user`) → 에이전트가 `sudo -n`으로 직접 실행. `lnx-victim`은 비밀번호 필요(권한 상승 시나리오 보존을 위해 의도적으로 유지) → sudo 작업은 사용자에게 명령을 안내한다.

- Kali는 netplan이 아니라 NetworkManager 사용. eth0 = NAT(DHCP), eth1 = VMnet2 고정, `ipv4.never-default yes`.

예: `ssh splunk 'sudo -u splunk /opt/splunk/bin/splunk status'`

- 호스트(10.10.10.1)에서 들어오는 SSH는 관리용 세션이다. Splunk에서 탐지 룰을 만들 때 공격 트래픽과 구분하도록 태그를 붙이거나 제외한다.

## Splunk 주의사항
- root 실행 거부됨 → `/opt/splunk`를 `splunk` 사용자 소유로 chown, `sudo -u splunk`로 실행.

## 진행 상황
- [x] VMware 가상 네트워크 구성
- [x] splunk / lnx-victim VM 기본 세팅
- [x] Splunk 10.6 설치, 수신 9997, 인덱스 `wineventlog`/`sysmon`/`linux`, TA(windows/sysmon/nix) + CIM 설치 (라이선스: Enterprise Trial)
- [x] 로그 수집: win-victim(호스트명 `win-vic`, UF + Sysmon → `wineventlog`/`sysmon`, sourcetype `XmlWinEventLog`), lnx-victim(UF → `linux`: audit.log, auth.log, syslog)
- [x] GitHub 저장소: https://github.com/P0LESTAR/splunk-siem-lab (private, `main`). `gh`는 `%LOCALAPPDATA%\ghcli\bin`(PATH 미등록)
- 라이선스: Enterprise Trial(2026-10-08 시작, 약 12/7 만료) → 이후 Free 전환 예정. Free는 알림/예약 검색 없음 → 알림 동작 캡처는 만료 전에 완료
- [ ] 공격 시뮬레이션 및 탐지 룰 작성 (저장된 검색 아직 없음)
- [ ] 포트폴리오 문서화

스냅샷: splunk `splunk 설치`, lnx-victim `splunk uf 초기셋팅`, kali `Snapshot 1`. win-victim VM은 암호화되어 있어 vmrun으로 조회 불가(콘솔에서 확인).
