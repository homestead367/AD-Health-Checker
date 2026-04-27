@echo off
PowerShell -Command "Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0AD_HealthCheck.ps1""' -Verb RunAs"
