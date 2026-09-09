@echo off
REM Launcher for the Cubic Castles live bot. Just run:  run
REM   - holds the fixed flags so you don't retype them
REM   - anything you add on the line is passed through, e.g.:  run --crawl-delay 5
REM %~dp0 = this file's folder, so it works from any directory.
python "%~dp0stage2\cc_client.py" live ^
  --i-accept-live-risk ^
  --control-port 8777 ^
  --control-host 0.0.0.0 ^
  --control-token pickAsecret ^
  %*
