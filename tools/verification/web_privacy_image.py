"""Real shipped proxy canaries: no upstream service or external requests needed."""
import argparse
import http.client
import json
import subprocess
import time
import uuid
from pathlib import Path


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--image",required=True)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    name="mk-web-privacy-"+uuid.uuid4().hex
    report={"scope":"synthetic HTTP against built web image; deliberately unavailable loopback upstream"}
    created=False
    def docker(*parts):
        result=subprocess.run(["docker",*parts],check=True,capture_output=True,text=True,timeout=60)
        return result.stdout+(result.stderr if parts[0]=="logs" else "")
    try:
        report["image_id"]=json.loads(docker("image","inspect",args.image))[0]["Id"]
        docker("run","-d","--name",name,"--label","codex.task=mk-87-rows","--read-only",
            "--tmpfs","/var/cache/nginx","--tmpfs","/var/run","--tmpfs","/tmp",
            "--memory","128m","--cpus","1","--pids-limit","64",
            "--add-host","api:127.0.0.1","--publish","127.0.0.1::80",args.image)
        created=True
        port=int(json.loads(docker("inspect",name))[0]["NetworkSettings"]["Ports"]["80/tcp"][0]["HostPort"])
        canary="SYNTHETIC-PRIVATE-PROXY-"+uuid.uuid4().hex
        def request(method,path):
            connection=http.client.HTTPConnection("127.0.0.1",port,timeout=3)
            try:
                connection.request(method,path,headers={"Host":canary+".invalid","User-Agent":canary,
                    "Authorization":"Bearer "+canary,"Referer":"https://example.invalid/"+canary})
                response=connection.getresponse()
                response.read()
                return response.status
            finally: connection.close()
        deadline=time.monotonic()+15
        while True:
            try:
                if request("GET","/")==200: break
            except (OSError,http.client.HTTPException): pass
            if time.monotonic()>deadline: raise AssertionError("owned web image not ready")
            time.sleep(.1)
        report["statuses"]={"spa":request("GET","/"+canary+"?private="+canary),
            "failed_upstream":request("GET","/api/"+canary+"?private="+canary),
            "custom_method":request(canary,"/")}
        assert report["statuses"]=={"spa":200,"failed_upstream":502,"custom_method":400}
        deadline=time.monotonic()+3
        while True:
            logs=docker("logs",name)
            if canary in logs or logs.count("http_request method=")>=4 or time.monotonic()>deadline: break
            time.sleep(.1)
        (args.output/"container.log").write_text(logs,encoding="utf-8")
        report["canary_absent"]=canary not in logs
        report["safe_request_count"]=logs.count("http_request method=")
        report["unavailable_upstream_visible"]="surface=api status=502" in logs
        report["custom_method_normalized"]="method=OTHER" in logs
        assert report["canary_absent"] and report["safe_request_count"]>=4
        assert report["unavailable_upstream_visible"] and report["custom_method_normalized"]
        report["outcome"]="Worked"
    except Exception as exc:
        report.update(outcome="Failed",error_type=type(exc).__name__)
        raise
    finally:
        if created:
            (args.output/"container.log").write_text(docker("logs",name),encoding="utf-8")
            docker("rm","--force",name)
        report["owned_container_removed"]=True
        (args.output/"report.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report))


if __name__=="__main__": main()
