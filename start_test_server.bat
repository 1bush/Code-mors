@echo off
setlocal
cd /d "%~dp0"
echo ==========================================================
echo  CODE MORS - server testimi (web + relay, nje port)
echo ==========================================================
echo.
if not exist "certs\cert.pem" (
  echo [1/3] Gjenerimi i certifikates self-signed ^(per kamera/HTTPS^)...
  call node tools\make_cert.js
  if errorlevel 1 (
    echo.
    echo  Certifikata nuk u krijua. Po vazhdoj me HTTP.
    echo  Shenim: pa HTTPS kamera nuk hapet; perdor ngjitjen manuale te linkut.
    echo.
    goto runhttp
  )
) else (
  echo [1/3] Certifikata ekziston: certs\cert.pem
)
echo.
echo [2/3] Hapja e portes ne Windows Firewall (kerkon leje admin, opsionale)...
netsh advfirewall firewall show rule name="CodeMors Test 8443" >nul 2>&1
if errorlevel 1 (
  netsh advfirewall firewall add rule name="CodeMors Test 8443" dir=in action=allow protocol=TCP localport=8443 >nul 2>&1
  if errorlevel 1 (echo   Nuk u shtua rregulli^(pa admin^). Shtoje manualisht nese telefoni nuk lidhet.) else (echo   Rregulli u shtua: TCP 8443.)
) else (
  echo   Rregulli ekziston.
)
echo.
echo [3/3] Nisja e serverit...
echo.
node test-server.js
goto :eof

:runhttp
node test-server.js --http --port 8080
goto :eof