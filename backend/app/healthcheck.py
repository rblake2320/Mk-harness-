"""Container liveness probe; standard library, no runtime database privileges."""
import urllib.request


def main():
    with urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=4) as response:
        if response.status != 200 or response.read(256) != b'{"status":"ok"}':
            raise SystemExit(1)


if __name__ == "__main__":
    main()
