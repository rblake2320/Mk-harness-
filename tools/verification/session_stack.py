"""Owned, loopback-only S2 stack. No provider credentials or outbound adapters.

Run under Linux/WSL; serve the built web UI separately. Ctrl-C stops only the
children this process started. The private temporary SQLite file is removed.
"""
import argparse
import base64
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import uuid
import json
import sqlite3
from urllib.parse import urlsplit

import httpx
import psycopg
from psycopg import sql
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    database = os.environ['MK_TEST_DATABASE_URL']
    parsed = urlsplit(database)
    if parsed.hostname != '127.0.0.1' or parsed.port != 5547 or parsed.path != '/mk_resolution_test':
        raise RuntimeError('This retained recipe accepts only the task-owned acceptance database on port 5547')
    repo = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=True)
    seed = secrets.token_bytes(32)
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    def b64(raw):
        return base64.urlsafe_b64encode(raw).decode().rstrip('=')
    master = base64.b64encode(secrets.token_bytes(32)).decode()
    owned_database = 'mk_s2_browser_' + uuid.uuid4().hex
    owned_url = database.replace('/mk_resolution_test', '/' + owned_database)
    # Preserve runtime paths, not host application/provider credentials.
    clean = {key: value for key, value in os.environ.items() if key in ('PATH', 'LANG', 'LD_LIBRARY_PATH', 'SYSTEMROOT')}
    kernel_env = {**clean, 'MK_DATABASE_URL': owned_url, 'MK_MASTER_KEY': master,
        'MK_ASSERTION_KEYS': 'k1=' + b64(public), 'MK_BIND': '127.0.0.1:8099',
        'MK_APPROVAL_RP_ID': '127.0.0.1', 'MK_APPROVAL_ORIGINS': 'http://127.0.0.1:4189',
        'RUST_ACTION_KERNEL_ENABLED': '1'}
    children = []
    with psycopg.connect(database, autocommit=True) as owner:
        owner.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(owned_database)))
    with tempfile.TemporaryDirectory(prefix='mk-s2-session-') as scratch:
        app_env = {**clean, 'DATABASE_URL': f'sqlite:///{scratch}/app.db',
            'JWT_SECRET': secrets.token_hex(32), 'MASTER_KEY': master,
            'RUST_ACTION_KERNEL_URL': 'http://127.0.0.1:8099', 'KERNEL_ASSERTION_PRIVATE_KEY': b64(seed),
            'CORS_ORIGINS': 'http://127.0.0.1:4189', 'RATE_LIMIT_PER_MINUTE': '1000',
            'KERNEL_TIMEOUT_SECONDS': '2'}
        try:
            import sys
            with (args.output / 'migration.log').open('w') as log:
                subprocess.run([str(args.kernel)], cwd=scratch,
                    env={**kernel_env, 'MK_MIGRATE_ONLY': '1'}, stdout=log, stderr=subprocess.STDOUT, check=True)
            # Migrations use the owner only once; actual API statements run as
            # the restricted role, not the connection's owner identity.
            kernel_env['MK_DATABASE_URL'] = owned_url + '?options=-c%20role%3Dmk_kernel_api'
            for name, command, env, ready in [
                ('kernel', [str(args.kernel)], kernel_env, 'http://127.0.0.1:8099/health/live'),
                ('app', [sys.executable, '-m', 'uvicorn', 'app.main:app', '--app-dir', str(repo / 'backend'),
                         '--host', '127.0.0.1', '--port', '8019'], app_env, 'http://127.0.0.1:8019/api/health'),
            ]:
                with (args.output / f'{name}.log').open('w') as log:
                    child = subprocess.Popen(command, cwd=scratch, env=env, stdout=log, stderr=subprocess.STDOUT)
                children.append(child)
                for _ in range(100):
                    if child.poll() is not None:
                        raise RuntimeError(f'{name} exited; inspect its retained log')
                    try:
                        if httpx.get(ready, timeout=0.5).is_success:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError(f'{name} failed readiness')
            print('READY: owned app 8019, kernel 8099. No model or messaging provider. Ctrl-C to stop.', flush=True)
            while all(child.poll() is None for child in children):
                time.sleep(0.25)
        except KeyboardInterrupt:
            pass
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        child.kill(); child.wait(timeout=5)
            summary = {'database': owned_database, 'kernel_runtime_role': 'mk_kernel_api'}
            app_file = Path(scratch) / 'app.db'
            if app_file.exists():
                with sqlite3.connect(app_file) as db:
                    summary['revocations'] = db.execute('SELECT count(*), count(confirmed_at) FROM auth_revocations').fetchone()
                    summary['sessions'] = db.execute('SELECT count(*), count(revoked_at) FROM auth_sessions').fetchone()
            with psycopg.connect(owned_url + '?options=-c%20role%3Dmk_kernel_api') as runtime:
                summary['actual_runtime_identity'] = runtime.execute('SELECT current_user').fetchone()[0]
                summary['kernel_revocations'] = runtime.execute('SELECT count(*) FROM kernel.revocations').fetchone()[0]
            with psycopg.connect(database, autocommit=True) as owner:
                owner.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(owned_database)))
            summary['owned_database_removed'] = True
            (args.output / 'stack-summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
            print('STOPPED: owned children stopped; isolated kernel database dropped; private app database removed on exit.', flush=True)


if __name__ == '__main__':
    main()
