"""Exercise the shipped app image against the owned disposable PostgreSQL cluster.

No provider calls. Fresh random database/network/containers; cleanup only recorded
targets. The database container must carry the mk-87-rows task label.
"""
import argparse
import base64
import json
import hashlib
import hmac
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
    parser.add_argument("--rotate-seal", action="store_true")
    parser.add_argument("--erase", action="store_true")
    parser.add_argument("--audit-privacy", action="store_true")
    parser.add_argument("--billing-privacy", action="store_true")
    parser.add_argument("--browser-url", help="Local production web preview for the actual deletion UI drill")
    args = parser.parse_args()
    if args.erase and args.rotate_seal:
        parser.error("Run erasure and rotation as separate, independently retained drills")
    if args.billing_privacy and not args.erase:
        parser.error("Billing privacy verification requires the erasure drill")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"scope": "author-run shipped container, real PostgreSQL, real HTTP; synthetic fixtures only"}
    owned = "mk-app-image-" + uuid.uuid4().hex
    database = "mk_app_image_" + uuid.uuid4().hex
    restored_database = "mk_app_image_" + uuid.uuid4().hex
    restored_created = False
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
                       "APP_SEAL_KEYS": "", "RATE_LIMIT_PER_MINUTE": "10000"}
        if args.billing_privacy:
            # Only an incoming synthetic webhook is enabled. No Stripe API key
            # is supplied and this fixture never performs provider operations.
            runtime_env["STRIPE_WEBHOOK_SECRET"] = secrets.token_urlsafe(32)
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
            if args.erase:
                if args.billing_privacy:
                    billing_dsn = psycopg.conninfo.make_conninfo(admin, dbname=database, user="mk_app_login", password=runtime_pw)
                    with psycopg.connect(billing_dsn) as connection:
                        billing_user, billing_tenant = connection.execute(
                            "SELECT id,tenant_id FROM mk_app.users WHERE email='image@example.com'").fetchone()
                        connection.execute("""INSERT INTO mk_app.subscriptions
                            (id,tenant_id,user_id,stripe_customer_id,stripe_subscription_id,tier,interval,status,created_at,updated_at)
                            VALUES (%s,%s,%s,'cus_ImagePrivacy','sub_ImagePrivacy','solo','year','active',now(),now())
                            ON CONFLICT(user_id) DO UPDATE SET stripe_customer_id='cus_ImagePrivacy',
                                stripe_subscription_id='sub_ImagePrivacy',status='active'""",
                            (uuid.uuid4().hex, billing_tenant, billing_user))
                added = client.post(f"/api/customers/{customer_id}/destinations", headers=headers,
                                    json={"channel": "sms", "value": "+15005550006"})
                assert added.status_code == 201
                assert client.put("/api/keys/mine", headers=headers,
                                  json={"provider": "anthropic", "api_key": "synthetic-deletion-provider-key"}).status_code == 200
                backup = subprocess.run(["docker", "exec", args.database_container, "pg_dump", "-U", parsed["user"],
                                         "--format=custom", "--dbname", database], capture_output=True, timeout=45)
                assert backup.returncode == 0 and len(backup.stdout) > 1000
                report["pre_erasure_backup"] = {"sha256": hashlib.sha256(backup.stdout).hexdigest(), "bytes": len(backup.stdout)}
                from datetime import datetime, timezone
                not_before = datetime.now(timezone.utc).isoformat()
                if args.browser_url:
                    from urllib.parse import urlparse
                    assert urlparse(args.browser_url).hostname in {"localhost", "127.0.0.1"}
                    from playwright.sync_api import sync_playwright
                    with sync_playwright() as playwright:
                        browser = playwright.chromium.launch(headless=True)
                        page = browser.new_page(viewport={"width": 1280, "height": 900})
                        page_errors = []
                        page.on("pageerror", lambda error: page_errors.append(str(error)))
                        # Transparent loopback reverse proxy, NOT canned API data:
                        # each browser request hits the actual pinned image.
                        def proxy(route):
                            parsed_url = urlparse(route.request.url)
                            upstream = str(client.base_url).rstrip("/") + parsed_url.path
                            if parsed_url.query:
                                upstream += "?" + parsed_url.query
                            response = route.fetch(url=upstream)
                            route.fulfill(response=response)
                        page.route("**/api/**", proxy)
                        tokens_json = json.dumps(confirmed.json()["tokens"])
                        page.add_init_script("sessionStorage.setItem('mk_tokens'," + json.dumps(tokens_json) + "); sessionStorage.setItem('cs_ai_notice_seen','1');")
                        page.goto(args.browser_url)
                        page.get_by_role("navigation", name="Main").get_by_role("button", name="Settings", exact=True).click()
                        page.get_by_text("Delete my account", exact=True).click()
                        page.get_by_label("Confirm with your password").fill("SyntheticStrongPassword123!")
                        with page.expect_response(lambda response: response.request.method == "DELETE" and urlparse(response.url).path == "/api/account") as pending:
                            page.get_by_role("button", name="Delete account", exact=True).click()
                        deleted = pending.value
                        receipt = deleted.json()
                        assert deleted.status == 202
                        page.get_by_role("heading", name="Deletion request accepted").wait_for()
                        assert page.evaluate("sessionStorage.getItem('mk_tokens')") is None
                        page.screenshot(path=str(output / "deleted-account-receipt.png"), full_page=True)
                        page.set_viewport_size({"width": 360, "height": 780})
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                        page.screenshot(path=str(output / "deleted-account-receipt-360.png"), full_page=True)
                        with page.expect_download() as downloaded:
                            page.get_by_role("button", name="Save deletion receipt", exact=True).click()
                        assert downloaded.value.suggested_filename == "deletion-receipt.json"
                        report["browser"] = {"actual_image_api": True, "auth_storage_cleared": True,
                            "receipt_download": True, "mobile_overflow": False, "page_errors": page_errors}
                        assert not page_errors
                        browser.close()
                else:
                    deleted = client.request("DELETE", "/api/account", headers=headers, json={"password": "SyntheticStrongPassword123!"})
                    assert deleted.status_code == 202, f"Account deletion returned {deleted.status_code}"
                    receipt = deleted.json()
                assert receipt["status"] == "pending_downstream"
                report["deletion_status"] = 202
                report["downstream_pending"] = receipt["pending"]
                report["deleted_session_status"] = client.get("/api/customers", headers=headers).status_code
                assert report["deleted_session_status"] == 401
                status = client.post("/api/account/erasure-status", json={"status_token": receipt["status_token"]})
                assert status.status_code == 200 and status.json()["request_id"] == receipt["request_id"]
                report["unauthenticated_receipt_status"] = status.status_code
                if args.billing_privacy:
                    billing_query = "SELECT status,stripe_customer_id,stripe_subscription_id,first_paid_at,updated_at FROM mk_app.subscriptions WHERE user_id=%s"
                    with psycopg.connect(billing_dsn) as connection:
                        frozen_billing = connection.execute(billing_query, (billing_user,)).fetchone()
                        assert frozen_billing[0] == "deletion_pending"
                        event_statuses = {}
                        for event_type in ("checkout.session.completed", "customer.subscription.created",
                                "customer.subscription.updated", "customer.subscription.deleted", "invoice.paid", "invoice.payment_succeeded"):
                            payload = json.dumps({"type": event_type, "data": {"object": {
                                "id": "sub_MustNotRevive", "customer": "cus_ImagePrivacy", "subscription": "sub_MustNotRevive",
                                "client_reference_id": billing_user, "status": "active"}}}).encode()
                            stamp = int(time.time())
                            signature = hmac.new(runtime_env["STRIPE_WEBHOOK_SECRET"].encode(), str(stamp).encode() + b"." + payload, hashlib.sha256).hexdigest()
                            reply = client.post("/api/billing/webhook", content=payload,
                                headers={"Stripe-Signature": f"t={stamp},v1={signature}", "Content-Type": "application/json"})
                            event_statuses[event_type] = reply.status_code
                            report["billing_late_webhook_statuses"] = event_statuses
                            assert reply.status_code == 200
                            assert connection.execute(billing_query, (billing_user,)).fetchone() == frozen_billing
                    report["billing_erasure_mirror_unchanged"] = True
                exporter = ("import sys; from sqlalchemy.orm import Session; from app.db import init_engine; "
                            "from app.tools.privacy_ledger import export_ledger; "
                            "s=Session(init_engine()); sys.stdout.buffer.write(export_ledger(s)); s.close()")
                raw_ledger = (once(["python", "-c", exporter], runtime_env) + "\n").encode()
                ledger_sha = hashlib.sha256(raw_ledger).hexdigest()
                report["external_ledger"] = {"sha256": ledger_sha, "bytes": len(raw_ledger),
                                             "requests": len(json.loads(raw_ledger)["requests"])}
                with psycopg.connect(admin, autocommit=True) as conn:
                    conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restored_database)))
                    restored_created = True
                restored = subprocess.run(["docker", "exec", "-i", args.database_container, "pg_restore", "-U", parsed["user"],
                                           "--exit-on-error", "--dbname", restored_database], input=backup.stdout,
                                          capture_output=True, timeout=45)
                assert restored.returncode == 0
                once(["python", "-m", "app.migrate", "bootstrap"], {
                    **env, "DB_NAME": restored_database, "MK_APP_BOOTSTRAP_USER": parsed["user"],
                    "MK_APP_BOOTSTRAP_PASSWORD": parsed["password"], "MK_APP_RUNTIME_PASSWORD": runtime_pw,
                    "MK_APP_MIGRATION_PASSWORD": migration_pw})
                restored_runtime_dsn = psycopg.conninfo.make_conninfo(admin, dbname=restored_database, user="mk_app_login", password=runtime_pw)
                def privacy_counts():
                    with psycopg.connect(restored_runtime_dsn) as conn:
                        return {name: conn.execute(sql.SQL("SELECT count(*) FROM mk_app.{}").format(sql.Identifier(name))).fetchone()[0]
                                for name in ("customers", "customer_destinations", "provider_keys", "auth_factors", "erasure_requests")}
                report["restored_before_ledger"] = privacy_counts()
                assert all(report["restored_before_ledger"][name] == 1 for name in ("customers", "customer_destinations", "provider_keys", "auth_factors"))
                restore_env = {**runtime_env, "DB_NAME": restored_database,
                    "PRIVACY_LEDGER_B64": base64.b64encode(raw_ledger).decode(),
                    "PRIVACY_LEDGER_SHA": ledger_sha, "PRIVACY_LEDGER_NOT_BEFORE": not_before}
                replayer = ("import os,base64,json; from sqlalchemy.orm import Session; from app.db import init_engine; "
                    "from app.tools.privacy_ledger import load_ledger,replay_ledger,timestamp; "
                    "rows=load_ledger(base64.b64decode(os.environ['PRIVACY_LEDGER_B64']),os.environ['PRIVACY_LEDGER_SHA'],timestamp(os.environ['PRIVACY_LEDGER_NOT_BEFORE'])); "
                    "s=Session(init_engine()); result=replay_ledger(s,rows,apply=True); s.commit(); print(json.dumps(result)); s.close()")
                report["restore_erasure_replay"] = json.loads(once(["python", "-c", replayer], restore_env))
                report["restored_after_ledger"] = privacy_counts()
                assert all(report["restored_after_ledger"][name] == 0 for name in ("customers", "customer_destinations", "provider_keys", "auth_factors"))
                report["restore_erasure_repeat"] = json.loads(once(["python", "-c", replayer], restore_env))
                assert report["restored_after_ledger"]["erasure_requests"] == 2
                if args.billing_privacy:
                    report["restored_billing_reactivation_refused"] = False
                    with psycopg.connect(restored_runtime_dsn) as connection:
                        assert connection.execute("SELECT status FROM mk_app.subscriptions WHERE user_id=%s", (billing_user,)).fetchone()[0] == "deletion_pending"
                        try:
                            connection.execute("UPDATE mk_app.subscriptions SET status='active' WHERE user_id=%s", (billing_user,))
                        except psycopg.errors.CheckViolation as exc:
                            report["restored_billing_reactivation_refused"] = "PRIVACY_BILLING_FROZEN" in str(exc)
                            connection.rollback()
                    assert report["restored_billing_reactivation_refused"]
            if args.rotate_seal:
                created_key = client.put("/api/keys/mine", headers=headers,
                                         json={"provider": "anthropic", "api_key": "synthetic-image-provider-key"})
                assert created_key.status_code == 200
                backup = subprocess.run(["docker", "exec", args.database_container, "pg_dump", "-U", parsed["user"],
                                         "--format=custom", "--dbname", database], capture_output=True, timeout=45)
                assert backup.returncode == 0 and len(backup.stdout) > 1000
                report["pre_rotation_backup"] = {"sha256": hashlib.sha256(backup.stdout).hexdigest(), "bytes": len(backup.stdout)}
                seal_key = base64.b64encode(secrets.token_bytes(32)).decode()
                ring = "s2=" + seal_key + ",m0=master"
                migration_url = f"postgresql+psycopg://mk_app_migrator:{migration_pw}@db:5432/{database}?sslmode=disable"
                report["seal_activation"] = json.loads(once(["python", "-m", "app.tools.reseal", "activate", "--actor", "image-acceptance"],
                    {"APP_SEAL_KEYS": ring, "MASTER_KEY": runtime_env["MASTER_KEY"], "MK_APP_MIGRATION_URL": migration_url}))
                # The already-running old-key process is denied by PostgreSQL.
                stale = client.put("/api/keys/mine", headers=headers,
                                   json={"provider": "anthropic", "api_key": "obsolete-writer-value"})
                report["retired_writer_status"] = stale.status_code
                assert stale.status_code == 503 and stale.json()["detail"]["code"] == "SEAL_WRITER_RETIRED"
                docker("rm", "--force", app_name)
                app_created = False
                runtime_env["APP_SEAL_KEYS"] = ring
                report["reseal"] = json.loads(once(["python", "-m", "app.tools.reseal", "rekey", "--batch-size", "1", "--actor", "image-acceptance"], runtime_env))
                assert report["reseal"]["stale"] == report["reseal"]["unreadable"] == 0
                runtime_env["APP_SEAL_KEYS"] = "s2=" + seal_key
                report["retired_key_status"] = json.loads(once(["python", "-m", "app.tools.reseal", "status"], runtime_env))
                docker(*options, image, env=runtime_env)
                app_created = True
                rolled = json.loads(docker("inspect", app_name))[0]
                client.base_url = "http://127.0.0.1:" + rolled["NetworkSettings"]["Ports"]["8000/tcp"][0]["HostPort"]
                ready()
                report["session_survives_reseal"] = client.get("/api/customers/" + customer_id, headers=headers).status_code
                assert report["session_survives_reseal"] == 200
                login = client.post("/api/auth/login", json={"email": "image@example.com", "password": "SyntheticStrongPassword123!"})
                assert login.status_code == 200
                verified = client.post("/api/auth/mfa/verify", headers={"Authorization": "Bearer " + login.json()["access_token"]},
                                       json={"code": pyotp.TOTP(enrolled.json()["secret"]).at(time.time() + 30)})
                report["totp_after_key_retirement"] = verified.status_code
                assert verified.status_code == 200
                with psycopg.connect(admin, autocommit=True) as conn:
                    conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restored_database)))
                    restored_created = True
                restored = subprocess.run(["docker", "exec", "-i", args.database_container, "pg_restore", "-U", parsed["user"],
                                           "--exit-on-error", "--dbname", restored_database], input=backup.stdout,
                                          capture_output=True, timeout=45)
                assert restored.returncode == 0, "Restore of the synthetic pre-rotation backup failed"
                restore_env = {**runtime_env, "DB_NAME": restored_database}
                restored_runtime_dsn = psycopg.conninfo.make_conninfo(admin, dbname=restored_database, user="mk_app_login", password=runtime_pw)
                with psycopg.connect(restored_runtime_dsn) as conn:
                    report["fresh_restore_default_temp_privilege"] = conn.execute("SELECT has_database_privilege(current_database(),'TEMP')").fetchone()[0]
                assert report["fresh_restore_default_temp_privilege"] is True
                # pg_dump without --create does not restore database-wide ACLs.
                # Reapply operator bootstrap before using the restored database.
                once(["python", "-m", "app.migrate", "bootstrap"], {
                    **env, "DB_NAME": restored_database, "MK_APP_BOOTSTRAP_USER": parsed["user"],
                    "MK_APP_BOOTSTRAP_PASSWORD": parsed["password"], "MK_APP_RUNTIME_PASSWORD": runtime_pw,
                    "MK_APP_MIGRATION_PASSWORD": migration_pw})
                with psycopg.connect(restored_runtime_dsn) as conn:
                    report["restore_temp_privilege_after_bootstrap"] = conn.execute("SELECT has_database_privilege(current_database(),'TEMP')").fetchone()[0]
                assert report["restore_temp_privilege_after_bootstrap"] is False
                rejected = json.loads(once(["python", "-m", "app.tools.reseal", "status"], restore_env, expected=1))
                assert rejected["unreadable"] == 2
                report["old_backup_without_escrow_unreadable"] = rejected["unreadable"]
                restore_env["APP_SEAL_KEYS"] = ring
                restore_url = f"postgresql+psycopg://mk_app_migrator:{migration_pw}@db:5432/{restored_database}?sslmode=disable"
                once(["python", "-m", "app.tools.reseal", "activate", "--actor", "restore-acceptance"],
                     {"APP_SEAL_KEYS": ring, "MASTER_KEY": runtime_env["MASTER_KEY"], "MK_APP_MIGRATION_URL": restore_url})
                report["restored_backup_reseal"] = json.loads(once(["python", "-m", "app.tools.reseal", "rekey", "--actor", "restore-acceptance"], restore_env))
                restore_env["APP_SEAL_KEYS"] = runtime_env["APP_SEAL_KEYS"]
                report["restored_backup_new_key_only"] = json.loads(once(["python", "-m", "app.tools.reseal", "status"], restore_env))
                assert report["restored_backup_new_key_only"]["unreadable"] == 0
            if args.audit_privacy:
                canary="SYNTHETIC-PRIVATE-URL-"+uuid.uuid4().hex
                assert client.get("/api/health/ready",params={"customer":canary}).status_code==200
                assert client.get("/"+canary).status_code==404
                logs=docker("logs",app_name)
                report["audit_privacy"]={"url_canary_absent_from_logs":canary not in logs,
                    "safe_request_events_present":"http_request method=" in logs}
                assert report["audit_privacy"]["url_canary_absent_from_logs"]
                assert report["audit_privacy"]["safe_request_events_present"]
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
        if restored_created:
            with psycopg.connect(admin, autocommit=True) as conn:
                conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(restored_database)))
        report["owned_targets_removed"] = True
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
