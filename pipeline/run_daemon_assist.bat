@echo off
rem Демон L1-триажа, режим assist: запуск вручную или через Планировщик задач.
rem Модель из MODEL, без размышления, опрос Wazuh каждые 30 с. Только чтение Wazuh.
setlocal
if not defined MODEL set MODEL=kezekshi-l1-v6
set KEZEKSHI_AUTOCLOSE=assist
set TRIAGE_THINK=0
set KEZEKSHI_PY=1
cd /d %~dp0
if not exist out mkdir out
echo === start %DATE% %TIME% (assist, interval 30) >> out\daemon_service.log
python run.py --interval 30 >> out\daemon_service.log 2>&1
echo === stop %DATE% %TIME% exit %ERRORLEVEL% >> out\daemon_service.log
