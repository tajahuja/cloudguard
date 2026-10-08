"""Verify a real Streamlit HTTP server; shut down only the child started here."""
import subprocess
import sys
import time
from urllib.request import urlopen
from cloudguard.config import ROOT


def main():
    process = subprocess.Popen(
        [sys.executable, '-m', 'streamlit', 'run', 'dashboard/app.py',
         '--server.address', '127.0.0.1', '--server.port', '8504',
         '--server.headless', 'true', '--browser.gatherUsageStats', 'false'],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for attempt in range(40):
            try:
                with urlopen('http://127.0.0.1:8504/_stcore/health', timeout=1) as response:
                    assert response.read() == b'ok'
                with urlopen('http://127.0.0.1:8504/', timeout=2) as response:
                    assert '<html' in response.read().decode().lower()
                print('CloudGuard Streamlit server launch and HTTP readiness verified.')
                return
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError('Streamlit exited before readiness.') from None
                time.sleep(0.25)
        raise RuntimeError('Streamlit did not become ready.')
    finally:
        process.terminate()
        process.wait(timeout=10)


if __name__ == '__main__':
    main()
