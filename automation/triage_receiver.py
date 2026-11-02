"""Loopback-only lab receiver. This stage saves webhooks; it does not triage them."""
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import uuid


def create_server(port, output_dir):
    output_dir = Path(output_dir).expanduser().resolve()
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def respond(self, status, message):
            body = json.dumps({'status': message}).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != '/webhook/splunk':
                self.respond(404, 'not_found')
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                self.respond(400, 'invalid_length')
                return
            if length <= 0 or length > 65536:
                self.respond(413 if length > 65536 else 400, 'invalid_size')
                return
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    self.respond(400, 'incomplete_body')
                    return
                payload = json.loads(raw)
            except (ValueError, UnicodeError):
                self.respond(400, 'invalid_json')
                return
            except OSError:
                self.respond(408, 'read_timeout')
                return
            if (not isinstance(payload, dict)
                    or not isinstance(payload.get('sid'), str)
                    or not payload['sid'].strip()
                    or not isinstance(payload.get('result'), dict)):
                self.respond(400, 'invalid_payload')
                return
            now = datetime.now(timezone.utc)
            name = now.strftime('%Y%m%dT%H%M%S%fZ') + '_' + uuid.uuid4().hex
            temporary = output_dir / (name + '.tmp')
            target = output_dir / (name + '.json')
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                    json.dump({'received_at': now.isoformat(), 'payload': payload},
                              stream, ensure_ascii=False, indent=2)
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary.replace(target)
            except OSError:
                temporary.unlink(missing_ok=True)
                self.respond(500, 'storage_error')
                return
            print('saved: ' + target.name, flush=True)
            self.respond(200, 'saved')

        def log_message(self, format, *args):
            # Do not print request URLs, headers or payloads.
            pass

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=18080)
    parser.add_argument('--output-dir', type=Path,
                        default=Path.home() / 'splunk-triage' / 'inbox')
    args = parser.parse_args()
    server = create_server(args.port, args.output_dir)
    print(f'Listening: http://127.0.0.1:{server.server_port}/webhook/splunk', flush=True)
    print(f'Output: {args.output_dir.expanduser().resolve()}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
