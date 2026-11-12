@echo off
rem Double-click this file to start dweb-gateway
cd /d "%~dp0"
python start.py
if errorlevel 1 pause
