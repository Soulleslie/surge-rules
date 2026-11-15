"""Load every actual MRS in a real mihomo process and inspect its provider API.

Run explicitly, not as an offline unit test. Uses loopback only; no user traffic
or Surge device is involved. Classical Extra files are covered by split tests
and generation, not by this binary-format smoke test.
"""

import argparse
import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


def run(binary, root):
    paths = sorted((root / 'clash').glob('*.mrs'))
    if not paths:
        raise RuntimeError('No MRS files to validate')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    providers = {}
    for path in paths:
        providers[path.stem] = {'type': 'file', 'behavior': 'ipcidr' if path.stem.endswith('-IP') else 'domain',
                                'format': 'mrs', 'path': str(path.resolve())}
    config = {'mode': 'rule', 'log-level': 'warning', 'external-controller': f'127.0.0.1:{port}',
              'dns': {'enable': False}, 'rule-providers': providers,
              'rules': [f'RULE-SET,{name},DIRECT' for name in providers] + ['MATCH,DIRECT']}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name, provider in providers.items():
            target = tmp / f'{name}.mrs'
            shutil.copyfile(provider['path'], target)
            provider['path'] = str(target)
        cfg = tmp / 'config.json'
        cfg.write_text(json.dumps(config))
        with (tmp / 'mihomo.log').open('w+') as log:
            process = subprocess.Popen([str(Path(binary).resolve()), '-d', str(tmp), '-f', str(cfg)],
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                # Do not inherit HTTP_PROXY for this deliberately local API.
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                deadline = time.monotonic() + 15
                actual = None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        break
                    try:
                        with opener.open(f'http://127.0.0.1:{port}/providers/rules', timeout=1) as resp:
                            actual = json.load(resp)['providers'] or {}
                        if set(providers) <= set(actual) and all(actual[n].get('ruleCount', 0) > 0 for n in providers):
                            break
                    except (OSError, ValueError, KeyError):
                        pass
                    time.sleep(0.1)
                if actual is None or not set(providers) <= set(actual):
                    raise RuntimeError('Not all MRS providers loaded')
                for name in providers:
                    if actual[name].get('ruleCount', 0) <= 0:
                        raise RuntimeError(f'Empty or invalid MRS provider: {name}')
                print(f'PASS: real mihomo loaded {len(providers)} nonempty MRS providers via its API')
            except Exception:
                log.flush(); log.seek(0)
                print(log.read()[-6000:])
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    run(args.mihomo, args.root)
