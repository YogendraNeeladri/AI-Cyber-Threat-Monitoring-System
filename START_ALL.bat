@echo off
title CyberThreat SOC - Launcher
color 0A
cls

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║     AI Cyber Threat Detection System v1.0        ║
echo  ║     Starting all services...                     ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: ── Check MongoDB ────────────────────────────────────────
echo  [1/4] Starting MongoDB...
start "MongoDB" cmd /k "mongod --dbpath C:\data\db"
timeout /t 3 /nobreak >nul
echo       MongoDB started on port 27017
echo.

:: ── Start Backend ─────────────────────────────────────────
echo  [2/4] Starting Node.js Backend...
start "Backend API" cmd /k "cd /d %~dp0backend && npm run dev"
timeout /t 4 /nobreak >nul
echo       Backend started on port 5000
echo.

:: ── Start AI Engine ───────────────────────────────────────
echo  [3/4] Starting Python AI Engine...
start "AI Engine" cmd /k "cd /d %~dp0ai-engine && python ai_server.py"
timeout /t 5 /nobreak >nul
echo       AI Engine started on port 7000
echo.

:: ── Start React Frontend ──────────────────────────────────
echo  [4/4] Starting React Dashboard...
start "Dashboard" cmd /k "cd /d %~dp0frontend && npm start"
timeout /t 6 /nobreak >nul
echo       Dashboard starting on port 3000
echo.

echo  ╔══════════════════════════════════════════════════╗
echo  ║  All services launched!                          ║
echo  ║                                                  ║
echo  ║  Dashboard  →  http://localhost:3000             ║
echo  ║  Backend    →  http://localhost:5000/api/health  ║
echo  ║  AI Engine  →  http://localhost:7000/health      ║
echo  ║                                                  ║
echo  ║  Login: admin@cyberthreat.local                  ║
echo  ║  Pass:  Admin@123456                             ║
echo  ╚══════════════════════════════════════════════════╝
echo.
pause