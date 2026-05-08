@echo off
title Stopping all CyberThreat services
color 0C
echo.
echo  Stopping all services...
echo.
taskkill /FI "WINDOWTITLE eq MongoDB*"     /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Backend API*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq AI Engine*"   /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Dashboard*"   /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Simulator*"   /F >nul 2>&1
echo  All services stopped.
echo.
pause