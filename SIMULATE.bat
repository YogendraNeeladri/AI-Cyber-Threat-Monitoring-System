@echo off
title CyberThreat SOC - Simulator Menu
color 0B
cls

:MENU
echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║     Telemetry Simulator — Choose Scenario        ║
echo  ╚══════════════════════════════════════════════════╝
echo.
echo   1.  Normal traffic    (low severity, 3s interval)
echo   2.  DDoS attack       (high volume,  0.25s interval)
echo   3.  APT               (slow stealthy critical, 7s)
echo   4.  Ransomware        (outbreak, 1.2s interval)
echo   5.  Insider threat    (internal IPs, 5s interval)
echo   6.  Brute force       (credential attack, 0.8s)
echo   7.  Mixed             (all types, 2s interval)
echo   8.  APT Kill Chain    (full lifecycle simulation)
echo   9.  Burst 100 events  (mixed, instant)
echo   0.  Exit
echo.
set /p choice=  Select scenario (0-9): 

if "%choice%"=="1" start "Simulator-Normal"     cmd /k "cd /d %~dp0ai-engine && python telemetry_simulator.py --scenario normal"
if "%choice%"=="2" start "Simulator-DDoS"       cmd /k "cd /d %~dp0ai-engine && python telemetry_simulator.py --scenario ddos"
if "%choice%"=="3" start "Simulator-APT"        cmd /k "cd /d %~dp0ai-engine && python telemetry_simulator.py --scenario apt"
if "%choice%"=="4" start "Simulator-Ransomware" cmd /k "cd /d %~dp0ai-engine && python telemetry_simulator.py --scenario ransomware"
if "%choice%"=="5" start "Simulator-Insider"    cmd /k "cd /d %~dp0ai-engine && python telemetry_simulator.py --scenario insider"
if "%choice%"=="6" start "Simulator-Brute"      cmd /k "cd /d %~dp0ai-engine && python telemetry_simulator.py --scenario bruteforce"
if "%choice%"=="7" start "Simulator-Mixed"      cmd /k "cd /d %~dp0ai-engine && python telemetry_simulator.py --scenario mixed"
if "%choice%"=="8" start "Simulator-KillChain"  cmd /k "cd /d %~dp0ai-engine && python telemetry_simulator.py --killchain"
if "%choice%"=="9" start "Simulator-Burst"      cmd /k "cd /d %~dp0ai-engine && python telemetry_simulator.py --burst 100 --scenario mixed"
if "%choice%"=="0" exit

goto MENU