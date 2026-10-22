"""Exercise the shipped app image against the owned disposable PostgreSQL cluster.

No provider calls. Fresh random database/network/containers; cleanup only recorded
targets. The database container must carry the mk-87-rows task label.
"""
import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import psycopg
import pyotp
from psycopg import sql


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--database-container", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"scope": "author-run shipped container, real PostgreSQL, real HTTP; synthetic fixtures only"}
    owned = "mk-app-image-" + uuid.uuid4().hex
    database = "mk_app_image_" + uuid.uuid4().hex
    app_name = owned + "-api"
    network_created = attached = app_created = database_created = False

    def docker(*parts, env=None, expected=0):
        result = subprocess.run(["docker", *parts], env={**os.environ, **(env or {})},
                                capture_output=True, text=True, timeout=90)
        if result.returncode != expected:
            raise RuntimeError(f"Docker {parts[0]} failed with {result.returncode}: {result.stderr[-1000:]}")
        return (result.stdout + (result.stderr if parts[0] == "logs" else "")).strip()

    def once(command, env, expected=0):
        options = ["run", "--rm", "--network", owned, "--read-only", "--cap-drop=ALL",
                   "--security-opt=no-new-privileges", "--label", "codex.task=mk-87-rows"]
        for key in env:
            options.extend(["--env", key])
        return docker(*options, image, *command, env=env, expected=expected)

    info = json.loads(docker("inspect", args.database_container))[0]
    assert info["Config"]["Labels"].get("codex.task") == "mk-87-rows"
    assert args.database_container == "mk-appdb-acceptance-20261022"
    image = json.loads(docker("image", "inspect", args.image))[0]["Id"]
    report["image_id"] = image
    admin = os.environ["MK_APP_TEST_ADMIN_DSN"]
    parsed = psycopg.conninfo.conninfo_to_dict(admin)
    assert parsed["host"] in {"localhost", "127.0.0.1"} and parsed["dbname"] == "mk_app_test_admin"
    env = {"DB_HOST": "db", "DB_NAME": database, "DB_SSLMODE": "disable"}
    runtime_pw, migration_pw = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    try:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
            database_created = True
        docker("network", "create", "--label", "codex.task=mk-87-rows", owned)
        network_created = True
        docker("network", "connect", "--alias", "db", owned, args.database_container)
        attached = True
        report["bootstrap"] = once(["python", "-m", "app.migrate", "bootstrap"], {
            **env, "MK_APP_BOOTSTRAP_USER": parsed["user"], "MK_APP_BOOTSTRAP_PASSWORD": parsed["password"],
            "MK_APP_RUNTIME_PASSWORD": runtime_pw, "MK_APP_MIGRATION_PASSWORD": migration_pw})
        migration_env = {**env, "MK_APP_MIGRATION_PASSWORD": migration_pw}
        report["migration"] = once(["python", "-m", "app.migrate", "upgrade"], migration_env)
        report["migration_repeat"] = once(["python", "-m", "app.migrate", "upgrade"], migration_env)
        report["owner_runtime_refused"] = "Unsafe runtime database identity" in once(
            ["python", "-c", "from app.db import init_engine;\ntry: init_engine()\nexcept RuntimeError as e: print(str(e)); raise SystemExit(1)"],
            {**env, "DB_USER": parsed["user"], "DB_PASSWORD": parsed["password"]}, expected=1)
        assert report["owner_runtime_refused"]
        runtime_env = {**env, "DB_USER": "mk_app_login", "DB_PASSWORD": runtime_pw,
                       "JWT_SECRET": secrets.token_urlsafe(40), "MASTER_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
                       "RATE_LIMIT_PER_MINUTE": "10000"}
        options = ["run", "--detach", "--name", app_name, "--network", owned, "--read-only",
                   "--cap-drop=ALL", "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                   "--label", "codex.task=mk-87-rows", "--publish", "127.0.0.1::8000"]
        for key in runtime_env:
            options.extend(["--env", key])
        docker(*options, image, env=runtime_env)
        app_created = True
        inspection = json.loads(docker("inspect", app_name))[0]
        port = inspection["NetworkSettings"]["Ports"]["8000/tcp"][0]["HostPort"]
        report["runtime"] = {"user": inspection["Config"]["User"], "read_only": inspection["HostConfig"]["ReadonlyRootfs"],
                             "cap_drop": inspection["HostConfig"]["CapDrop"]}
        assert report["runtime"]["user"] == "65532:65532" and report["runtime"]["read_only"]
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=10) as client:
            def ready():
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    try:
                        if client.get("/api/health/ready").status_code == 200:
                            return
                    except httpx.TransportError:
                        pass
                    time.sleep(.3)
                raise RuntimeError("Shipped application failed readiness")
            ready()
            signup = client.post("/api/auth/signup", json={"org_name": "Image fixture", "email": "image@example.com",
                                "password": "SyntheticStrongPassword123!", "key_policy": "both"})
            assert signup.status_code == 201
            headers = {"Authorization": "Bearer " + signup.json()["access_token"]}
            report["password_only_customer_status"] = client.get("/api/customers", headers=headers).status_code
            assert report["password_only_customer_status"] == 403
            enrolled = client.post("/api/auth/mfa/enroll", headers=headers)
            assert enrolled.status_code == 200
            confirmed = client.post("/api/auth/mfa/confirm", headers=headers,
                                    json={"code": pyotp.TOTP(enrolled.json()["secret"]).now()})
            assert confirmed.status_code == 200
            headers = {"Authorization": "Bearer " + confirmed.json()["tokens"]["access_token"]}
            created = client.post("/api/customers", headers=headers, json={"name": "Retained synthetic image customer"})
            assert created.status_code == 201
            report["customer_created_status"] = created.status_code
            customer_id = created.json()["id"]
            report["export_before_step_up"] = client.get("/api/customers/export.csv", headers=headers).status_code
            assert report["export_before_step_up"] == 403
            stepped = client.post("/api/auth/step-up", headers=headers, json={"password": "SyntheticStrongPassword123!",
                                  "recovery_code": confirmed.json()["recovery_codes"][0]})
            assert stepped.status_code == 200
            exported = client.get("/api/customers/export.csv", headers=headers)
            assert exported.status_code == 200 and "Retained synthetic image customer" in exported.text
            report["export_after_step_up"] = exported.status_code
            docker("exec", app_name, "python", "-m", "app.healthcheck")
            report["shipped_healthcheck_exit"] = 0
            docker("restart", app_name)
            restarted = json.loads(docker("inspect", app_name))[0]
            restart_port = restarted["NetworkSettings"]["Ports"]["8000/tcp"][0]["HostPort"]
            report["published_port_changed_after_restart"] = port != restart_port
            client.base_url = f"http://127.0.0.1:{restart_port}"
            ready()
            retained = client.get("/api/customers/" + customer_id, headers=headers)
            assert retained.status_code == 200 and retained.json()["name"] == "Retained synthetic image customer"
            report["after_restart_customer_status"] = retained.status_code
        live = psycopg.conninfo.make_conninfo(admin, dbname=database, user="mk_app_login", password=runtime_pw)
        with psycopg.connect(live) as conn:
            report["database_identity"] = conn.execute("SELECT session_user, current_user").fetchone()
            report["retained_customers"] = conn.execute("SELECT count(*) FROM mk_app.customers").fetchone()[0]
            report["audit_records"] = conn.execute("SELECT count(*) FROM mk_app.audit_logs").fetchone()[0]
        report["outcome"] = "Worked"
    except Exception as exc:
        report["outcome"] = "Failed"
        report["failure_class"] = type(exc).__name__
        raise
    finally:
        if app_created:
            (output / "container.log").write_text(docker("logs", app_name), encoding="utf-8")
            docker("rm", "--force", app_name)
        if attached:
            docker("network", "disconnect", owned, args.database_container)
        if network_created:
            docker("network", "rm", owned)
        if database_created:
            with psycopg.connect(admin, autocommit=True) as conn:
                conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))
        report["owned_targets_removed"] = True
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
