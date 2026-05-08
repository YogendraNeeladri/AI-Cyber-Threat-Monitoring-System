@echo off
title Seed database and run tests
color 0E
echo.
echo  [1/2] Seeding database with sample threats...
cd /d %~dp0backend
node config/seed.js
echo.
echo  [2/2] Running integration tests...
cd /d %~dp0ai-engine
python quick_test.py
echo.
pause