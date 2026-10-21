# Splunk SIEM Homelab

Splunk Enterprise 기반 SIEM 홈랩. 가상 환경에서 공격을 재현하고, 수집된 로그로 탐지 룰을 작성·튜닝하고, 대응 절차까지 문서화한다.

## 아키텍처

| VM | OS | IP (Host-only) | 역할 |
|---|---|---|---|
| splunk | Ubuntu Server | 10.10.10.10 | Splunk Enterprise 10.6 (인덱서 + 서치헤드) |
| win-vic | Windows 11 | 10.10.10.20 | Universal Forwarder + Sysmon |
| win10-vic | Windows 10 | 10.10.10.22 | Universal Forwarder + Sysmon, 레거시 엔드포인트 |
| linux-victim | Ubuntu | 10.10.10.21 | Universal Forwarder + auditd |
| kali | Kali Linux | 10.10.10.100 | 공격자 |

VM 이름은 OS 호스트명이자 Splunk `host` 필드 값과 같다.

- 랩 내부망: VMware Host-only `10.10.10.0/24` (DHCP 없음)
- 인터넷: 필요한 VM에만 NAT NIC 추가

## 데이터 수집

| 인덱스 | 소스 | sourcetype |
|---|---|---|
| `wineventlog` | Security, System, PowerShell/Operational, Defender/Operational | `XmlWinEventLog` |
| `sysmon` | Microsoft-Windows-Sysmon/Operational | `XmlWinEventLog` |
| `linux` | `/var/log/audit/audit.log`, `/var/log/auth.log`, `/var/log/syslog` | `linux:audit`, `linux_secure`, `syslog` |

설치 앱: Splunk Add-on for Microsoft Windows, Splunk Add-on for Sysmon, Splunk Add-on for Unix and Linux, Splunk Common Information Model

### Windows 10 피해자를 둔 이유

Windows 10은 2025년 10월에 지원이 종료됐지만 기업 환경에는 여전히 많이 남아 있다. `win10-vic`는 패치되지 않은 레거시 엔드포인트 역할을 하며, 탐지 룰을 Windows 10과 Windows 11 양쪽 로그로 검증하는 데 쓴다. 두 OS 모두 `XmlWinEventLog`라 필드 이름(`IpAddress`, `TargetUserName`, `LogonType` 등)이 같다.

### 로그 가시성 기준선 (win10-vic)

Windows 10 기본 감사 정책은 프로세스 생성(4688)을 기록하지 않는다. 그래서 고급 감사 하위 범주를 GUID로(OS 언어와 무관하게) 켜고, 4688에 명령줄을 남기도록 설정하고, PowerShell 스크립트 블록 로깅(4104)을 활성화해 가시성을 먼저 확보했다. 이후 `whoami` 실행 → Splunk 4688 수신까지 전 구간을 검증했다.

## 저장소 구조

```
configs/      Splunk 서버와 포워더 설정 파일
detections/   탐지 룰 (SPL)
docs/         시나리오별 보고서 (공격 → 로그 → 탐지 → 대응)
screenshots/  검색 결과와 대시보드 캡처
```

## 진행 상황

- [x] 가상 네트워크와 VM 구성
- [x] Splunk 설치와 로그 수집 (Windows, Sysmon, Linux)
- [ ] 탐지 시나리오와 룰 작성 (S3 완료)
- [ ] 대시보드
- [ ] 문서화
