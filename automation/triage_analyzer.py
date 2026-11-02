"""S3 evidence collector and deterministic summary. Standard library only."""
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SplunkClient:
    def __init__(self, base_url, token, *, ca_file=None, insecure_local=False, allow_test_http=False):
        parsed = urllib.parse.urlsplit(base_url)
        if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                or (parsed.scheme != 'https' and not
                    (allow_test_http and parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'))):
            raise ValueError('REST 주소는 자격 증명이나 경로가 없는 HTTPS origin이어야 합니다.')
        if insecure_local and parsed.hostname != '127.0.0.1':
            raise ValueError('인증서 검사 생략은 127.0.0.1 랩 연결에만 허용합니다.')
        if not token or any(character.isspace() for character in token):
            raise ValueError('유효한 토큰을 안전하게 입력해야 합니다.')
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.context = ssl.create_default_context(cafile=ca_file)
        if insecure_local:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=self.context))

    def request(self, path, data=None):
        url = self.base_url + path
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        request = urllib.request.Request(url, data=body, headers={'Authorization': 'Bearer ' + self.token})
        try:
            with self.opener.open(request, timeout=60) as response:
                raw = response.read(16777217)
            if len(raw) > 16777216:
                raise RuntimeError('REST 응답 크기 제한 초과')
            result = json.loads(raw)
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            raise RuntimeError(f'Splunk REST HTTP {code}: 인증·권한·주소 설정을 확인하세요.') from None
        except (urllib.error.URLError, OSError):
            raise RuntimeError('Splunk REST 연결 실패: 주소·포트·TLS 인증서 설정을 확인하세요.') from None
        except (ValueError, UnicodeError):
            raise RuntimeError('Splunk REST JSON 응답을 해석할 수 없습니다.') from None
        if not isinstance(result, dict):
            raise RuntimeError('예상과 다른 REST 응답 형식')
        if any(str(message.get('type', '')).upper() in ('ERROR', 'FATAL')
               for message in result.get('messages', []) if isinstance(message, dict)):
            raise RuntimeError('Splunk가 검색 오류를 반환했습니다. Splunk 검색 작업을 확인하세요.')
        return result

    def search(self, spl, earliest, latest, max_events=1000):
        created = self.request('/services/search/jobs', {
            'search': spl, 'earliest_time': f'{earliest:.3f}', 'latest_time': f'{latest:.3f}',
            'output_mode': 'json', 'exec_mode': 'blocking'})
        sid = created['sid']
        job = '/services/search/jobs/' + urllib.parse.quote(sid, safe='')
        info = self.request(job + '?output_mode=json')['entry'][0]['content']
        if str(info.get('isFinalized', '')).lower() in ('true', '1'):
            raise RuntimeError('검색이 강제 종료되었습니다. 불완전한 결과를 완료 보고서로 저장하지 않습니다.')
        if str(info.get('isDone', '')).lower() not in ('true', '1') or info.get('dispatchState') != 'DONE':
            raise RuntimeError('검색 작업이 완료되지 않았습니다. 완료 보고서를 생성하지 않습니다.')
        total = int(info['resultCount'])
        events = []
        while len(events) < min(total, max_events):
            query = urllib.parse.urlencode({'output_mode': 'json', 'offset': len(events),
                                           'count': min(200, max_events - len(events))})
            batch = self.request(job + '/results?' + query)['results']
            if not batch:
                break
            events.extend(batch)
        return sid, events[:max_events], total


def build_search(row):
    if not isinstance(row, dict) or not isinstance(row.get('host'), str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,255}', row['host']):
        raise ValueError('지원하지 않는 host 형식입니다. 값을 임의로 수정하지 말고 원본을 확인하세요.')
    guid_pattern = r'\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}'
    for name in ('ProcessGuid', 'ParentProcessGuid'):
        value = row.get(name)
        if (name == 'ProcessGuid' or value) and (not isinstance(value, str) or not re.fullmatch(guid_pattern, value)):
            raise ValueError(f'{name} 형식 오류. 원본 필드를 확인하세요.')
    host = row['host']
    guid = row['ProcessGuid']
    parent = row.get('ParentProcessGuid')
    process_filter = f'ProcessGuid="{guid}"'
    if parent:
        process_filter += f' OR ProcessGuid="{parent}"'
    return (
        f'search index=sysmon host="{host}" ('
        f'(EventCode=1 ({process_filter})) OR '
        f'(EventCode=10 SourceProcessGUID="{guid}" TargetImage="*lsass.exe") OR '
        f'(EventCode=3 ProcessGuid="{guid}")) '
        '| sort 0 _time '
        '| table _time _indextime host source EventCode EventRecordID ProcessGuid '
        'ParentProcessGuid Image ParentImage User CommandLine OriginalFileName '
        'SourceImage SourceProcessGUID TargetImage GrantedAccess DestinationIp DestinationPort Initiated')


def safe_cell(value):
    return str(value if value is not None else '미확인').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('\r', ' ').replace('\n', ' ')


def atomic_text(path, text):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def render_report(evidence):
    row = evidence['trigger']['result']
    events = evidence['events']
    accesses = [event for event in events if str(event.get('EventCode')) == '10'
                and str(event.get('SourceProcessGUID', '')).lower() == row['ProcessGuid'].lower()
                and str(event.get('TargetImage', '')).lower().endswith('\\lsass.exe')]
    lines = [
        '# S3 1차 트리아지 요약', '',
        f"- Alert: {safe_cell(evidence['trigger'].get('search_name', 'unknown'))}",
        f"- 호스트: {safe_cell(row['host'])}",
        f"- 원본 이벤트 시각(UTC): {datetime.fromtimestamp(float(row['_time']), timezone.utc).isoformat()}",
        f"- 실행 계정: {safe_cell(row.get('User'))}",
        f"- 실행 파일: {safe_cell(row.get('Image'))}",
        f"- 프로세스 GUID: {safe_cell(row['ProcessGuid'])}",
        f"- 부모 메타데이터: {safe_cell(row.get('ParentImage'))}",
        '- 탐지 기준: 기존 EID 1 Alert의 프로세스 생성 결과. LSASS 접근 자체와 구분한다.',
        '- 분석 대상: 이 Webhook의 result 1건. 같은 SID의 다른 결과 전체를 처리했다고 보장하지 않는다.', '',
        '## 1차 판단', '',
        '- LSASS 접근 관측' if accesses else '- 조회 범위에서 해당 프로세스의 LSASS 접근을 확인하지 못함',
        '- 자격 증명 추출 성공 여부는 판단할 수 없음. EID 10과 접근 마스크만으로 성공을 단정하지 않는다.',
        '- ATT&CK T1003.001은 조사 가설이며 프로세스 실행만으로 기법 수행을 확정하지 않는다.', '',
        '## 조회 범위와 한계', '',
        f"- 조회 시작(UTC): {datetime.fromtimestamp(evidence['earliest'], timezone.utc).isoformat()}",
        f"- 조회 종료(UTC): {datetime.fromtimestamp(evidence['latest'], timezone.utc).isoformat()}",
        f"- 반환 이벤트: {len(events)} / 검색 결과: {evidence['result_count']}",
        '- Sysmon EID 1(실행·직접 부모), 10(LSASS 접근), 3(해당 프로세스 네트워크)만 조회한다.',
        '- 네트워크 이벤트가 없더라도 연결이 없었다고 단정하지 않는다. EID 3 수집 정책 확인이 필요하다.',
        '- 부모가 조회 구간보다 먼저 생성되었으면 부모의 생성 이벤트가 누락될 수 있다.',
        '- 승인 작업 정보가 없으므로 정상 관리 작업 여부는 자동 확정하지 않는다.',
    ]
    if evidence['coverage_pending']:
        lines.append('- 후속 관찰 구간이 아직 끝나지 않았다. 즉시 재실행은 중복으로 건너뛰므로 --refresh로 재조회해야 한다.')
    if len(events) < evidence['result_count']:
        lines.append('- 결과 제한 또는 조회 불완전으로 일부 이벤트가 포함되지 않았다.')
    lines += ['', '## 타임라인', '',
              '| 근거 | _time (REST 원본) | EventCode | 프로세스 | 대상 / 연결 | 접근 권한 |',
              '|---|---|---|---|---|---|']
    for number, event in enumerate(events, 1):
        destination = event.get('TargetImage') or (str(event.get('DestinationIp', '')) + ':' + str(event.get('DestinationPort', ''))).strip(':')
        values = [f'E{number}', event.get('_time'), event.get('EventCode'),
                  event.get('Image') or event.get('SourceImage'), destination, event.get('GrantedAccess')]
        lines.append('| ' + ' | '.join(safe_cell(value) for value in values) + ' |')
    search_url = 'http://10.10.10.10:8000/en-US/app/search/search?' + urllib.parse.urlencode({
        'q': evidence['spl'], 'earliest': f"{evidence['earliest']:.3f}", 'latest': f"{evidence['latest']:.3f}"})
    lines += ['', '## 다음 조사', '',
              '- EID 1과 EID 10의 GUID, 호스트, 이벤트 시각을 대조하고 실행 경로·명령줄을 확인한다.',
              '- 실행 파일의 서명·출처 및 승인된 보안 점검 여부를 확인한다. 격리·종료는 자동 수행하지 않는다.',
              '- 실제 자격 증명·덤프·해시 출력은 수집하지 않는다.', '',
              '## 근거 조회', '', f'[동일 조건을 Splunk에서 검색]({search_url})',
              '- 상세 이벤트와 검색 SPL은 같은 폴더의 evidence.json에 보관한다.',
              '- E1, E2 등의 번호는 evidence.json의 events 배열 순서에 대응한다.',
              f"- 보강 검색 SID: {safe_cell(evidence['query_sid'])}",
              '- 원본 Webhook results_link는 자동으로 요청하지 않는다.', '']
    return '\n'.join(lines)


def run_file(input_file, client, output_dir, *, now=None, max_events=1000, refresh=False):
    envelope = json.loads(Path(input_file).read_text(encoding='utf-8'))
    payload = envelope['payload']
    row = payload['result']
    spl = build_search(row)
    try:
        event_time = float(row['_time'])
    except (KeyError, TypeError, ValueError):
        raise ValueError('숫자 형식의 원본 _time이 필요합니다.') from None
    current = time.time() if now is None else now
    if not math.isfinite(event_time) or event_time <= 0 or event_time > current:
        raise ValueError('원본 _time이 유효하지 않거나 현재보다 미래입니다. 시계를 확인하세요.')
    if not 1 <= max_events <= 10000:
        raise ValueError('max_events는 1~10000이어야 합니다.')
    earliest = event_time - 600
    latest = min(event_time + 120, current)
    identity = hashlib.sha256((row['host'].lower() + '|' + row['ProcessGuid'].lower()).encode()).hexdigest()
    directory = Path(output_dir).expanduser().resolve() / identity
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = directory / '.complete'
    if not refresh and marker.exists() and (directory / 'evidence.json').exists() and (directory / 'report.md').exists():
        return {'status': 'duplicate', 'directory': str(directory)}
    sid, events, total = client.search(spl, earliest, latest, max_events)
    evidence = {'trigger': payload, 'earliest': earliest, 'latest': latest,
                'coverage_pending': current < event_time + 120, 'spl': spl,
                'query_sid': sid, 'result_count': total, 'events': events}
    marker.unlink(missing_ok=True)
    atomic_text(directory / 'evidence.json', json.dumps(evidence, ensure_ascii=False, indent=2))
    atomic_text(directory / 'report.md', render_report(evidence))
    atomic_text(marker, 'complete\n')
    return {'status': 'created', 'directory': str(directory)}


def scan_once(inbox, client, output_dir, *, now=None):
    current = time.time() if now is None else now
    results = []
    for path in sorted(Path(inbox).expanduser().glob('*.json')):
        try:
            envelope = json.loads(path.read_text(encoding='utf-8'))
            payload = envelope['payload']
            if payload.get('search_name') == 'TEST_ONLY_receiver_check':
                results.append({'status': 'fixture', 'input': path.name})
                continue
            # Wait for the +2 minute observation interval and an extra minute for ingestion.
            if float(payload['result']['_time']) + 180 > current:
                results.append({'status': 'waiting', 'input': path.name})
                continue
            result = run_file(path, client, output_dir, now=current)
            result['input'] = path.name
            results.append(result)
        except (ValueError, KeyError, TypeError, OSError, RuntimeError) as error:
            results.append({'status': 'error', 'input': path.name, 'error': str(error)})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--input', type=Path, help='Analyze one saved webhook JSON')
    source.add_argument('--inbox', type=Path, help='Scan an inbox directory')
    parser.add_argument('--watch', action='store_true', help='Keep scanning; requires --inbox')
    parser.add_argument('--interval', type=int, default=30, help='Inbox scan interval in seconds')
    parser.add_argument('--output-dir', type=Path, default=Path.home() / 'splunk-triage' / 'reports')
    parser.add_argument('--base-url', default='https://127.0.0.1:8089')
    parser.add_argument('--ca-file', help='Trusted CA bundle for Splunk REST TLS')
    parser.add_argument('--insecure-local', action='store_true', help='Lab only: skip TLS verification on 127.0.0.1')
    parser.add_argument('--refresh', action='store_true', help='Re-query an existing report; --input only')
    args = parser.parse_args()
    if (args.watch and not args.inbox) or (args.refresh and not args.input) or args.interval < 5:
        parser.error('--watch requires --inbox, --refresh requires --input, interval must be >= 5')
    if args.inbox and not args.inbox.expanduser().is_dir():
        parser.error('Inbox directory does not exist')
    try:
        token = os.environ.get('SPLUNK_TOKEN') or getpass.getpass('Splunk API token (not echoed): ')
        client = SplunkClient(args.base_url, token, ca_file=args.ca_file, insecure_local=args.insecure_local)
        if args.insecure_local:
            print('WARNING: loopback lab TLS certificate verification is disabled.', file=sys.stderr)
        if args.input:
            print(json.dumps(run_file(args.input.expanduser(), client, args.output_dir, refresh=args.refresh), ensure_ascii=False))
            return 0
        print('Scanning inbox. Ctrl+C to stop. Only one analyzer instance should run.', flush=True)
        while True:
            results = scan_once(args.inbox, client, args.output_dir)
            for result in results:
                if result['status'] in ('created', 'error'):
                    print(json.dumps(result, ensure_ascii=False), flush=True)
            if not args.watch:
                return 1 if any(result['status'] == 'error' for result in results) else 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, EOFError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
