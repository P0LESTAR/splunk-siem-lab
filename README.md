# Splunk SIEM Homelab

Splunk Enterprise 기반 SIEM 홈랩. 가상 환경에서 공격을 재현하고, 수집된 로그로 탐지 룰을 작성·튜닝하고, 대응 절차까지 문서화한다.

## 아키텍처

| VM | OS | IP (Host-only) | 역할 |
|---|---|---|---|
| splunk | Ubuntu Server | 10.10.10.10 | Splunk Enterprise 10.6 (인덱서 + 서치헤드) |
| win-victim | Windows | 10.10.10.20 | Universal Forwarder + Sysmon |
| lnx-victim | Ubuntu | 10.10.10.21 | Universal Forwarder + auditd |
| kali | Kali Linux | 10.10.10.100 | 공격자 |

- 랩 내부망: VMware Host-only `10.10.10.0/24` (DHCP 없음)
- 인터넷: 필요한 VM에만 NAT NIC 추가

## 데이터 수집

| 인덱스 | 소스 | sourcetype |
|---|---|---|
| `wineventlog` | Security, System, PowerShell/Operational, Defender/Operational | `XmlWinEventLog` |
| `sysmon` | Microsoft-Windows-Sysmon/Operational | `XmlWinEventLog` |
| `linux` | `/var/log/audit/audit.log`, `/var/log/auth.log`, `/var/log/syslog` | `linux:audit`, `linux_secure`, `syslog` |

설치 앱: Splunk Add-on for Microsoft Windows, Splunk Add-on for Sysmon, Splunk Add-on for Unix and Linux, Splunk Common Information Model

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
- [ ] 탐지 시나리오와 룰 작성
- [ ] 대시보드
- [ ] 문서화
