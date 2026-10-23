@echo off
title MicroShield - Backend & Frontend

:: Chạy Backend trong CMD hiện tại
start "Backend - Python" cmd /k "python -m app.main --reload"

:: Mở CMD mới, chuyển vào frontend và chạy npm
start "Frontend - Vite" cmd /k "cd /d frontend && npm run dev"

exit