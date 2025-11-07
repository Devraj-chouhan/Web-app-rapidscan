# RapidScan Web UI

A Flask-based web interface that wraps the existing `rapidscan.py` CLI without modifying its logic. Streams live output to the browser and shows a progress bar.

## Prerequisites (Kali)
- Python 3.9+ (Kali has python3 by default)
- The same external tools RapidScan depends on (nmap, nikto, whatweb, wapiti, etc.) installed as you normally would on Kali.

## Setup
```bash
cd rapidscan/webapp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
python3 app.py
```
- Open http://127.0.0.1:8000
- Enter a target (domain or URL) and optionally a list of tools to skip.
- Click Start Scan. Logs will stream live; the progress bar updates based on the "Deploying X/Y" lines from RapidScan.

## Notes
- The web UI invokes: `python3 -u ../rapidscan.py -n [--skip ...] <target>`
  - `-n/--nospinner` disables RapidScan's spinner so logs are cleaner.
- Stopping a scan sends SIGINT to the subprocess. If a tool ignores it, the scan may take a moment to terminate.
- Reports and temp files are still created by RapidScan in its working directory as usual (e.g., `rs.vul.*`, `/tmp/rapidscan_temp_*`).
