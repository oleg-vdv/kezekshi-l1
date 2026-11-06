@echo off
rem Рабочее место дежурного: веб-пульт на http://127.0.0.1:8787 поверх журнала out/.
setlocal
cd /d %~dp0
if not exist out mkdir out
echo === start %DATE% %TIME% (console :8787) >> out\console_service.log
python console.py 8787 >> out\console_service.log 2>&1
echo === stop %DATE% %TIME% exit %ERRORLEVEL% >> out\console_service.log
