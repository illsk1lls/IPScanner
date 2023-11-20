@ECHO OFF&SETLOCAL ENABLEDELAYEDEXPANSION&SET "TitleName=IP Scanner"
TASKLIST /V /NH /FI "imagename eq cmd.exe"|FIND /I /C "%TitleName%">nul
IF NOT !errorlevel!==1 (ECHO ERROR:&ECHO IP Scanner is already open) |MSG * & EXIT /b
TITLE %TitleName%
>nul 2>&1 reg add hkcu\software\classes\.IPscanner\shell\runas\command /f /ve /d "cmd /x /d /r set \"f0=%%2\"& call \"%%2\" %%3"& set _= %*
>nul 2>&1 fltmc|| if "%f0%" neq "%~f0" (cd.>"%ProgramData%\runas.IPscanner" & start "%~n0" /high "%ProgramData%\runas.IPscanner" "%~f0" "%_:"=""%" & exit /b)
>nul 2>&1 reg delete hkcu\software\classes\.IPscanner\ /f &>nul 2>&1 del %ProgramData%\runas.IPscanner /f /q
>nul 2>&1 netsh advfirewall firewall set rule group=”Network Discovery” new enable=Yes
FOR /L %%# IN (1,1,20) DO (SET "EMPT=!EMPT! "&SET "FULL=!FULL!%%")
FOR /F %%a IN ('COPY/Z "%~dpf0" nul')DO FOR /F skip^=4 %%b IN ('ECHO;PROMPT;$H^|CMD')DO SET "BS=%%b"&SET "CR=%%a"
:LOAD
CALL :GETHOSTINFO
CALL :SCANSUBNETS
CALL :LISTMACHINES
SET "KEY="&ECHO.&ECHO Press any key to refresh, (X) to Exit
FOR /f "delims=" %%# IN ('2^> nul XCOPY /L /W /I "%~f0" "%~f0"') DO IF NOT DEFINED KEY SET "KEY=%%#"
IF /I "!KEY:~-1!"=="X" ENDLOCAL&GOTO :EOF
GOTO :LOAD
:GETCOMPUTERNAME <IP Address> <Return Var>
FOR /f "usebackq tokens=2" %%# IN (`PING -a %1 -n 1`) DO (SET %2=%%#)&EXIT /b
EXIT /b
:PROGRESS <Message> <% Per Cycle>
SET/A P+=%2
IF %P% GEQ 5 SET/A L=(%P%/5)+1&IF %P% GEQ 100 SET/A P=100
SET/P "=!CR!!BS!!CR![!FULL:~0,%L%!!BS!!EMPT:~%L%!]%~1 [%%%P%] "<nul
EXIT /b
:LISTMACHINES
SET/A SELF=0
CLS&ECHO  ExternalIP  : !EXT!&ECHO  InternalIP  : !ISHOST!&ECHO  Hostname    : !HOST!
ECHO.&ECHO     MAC ADDRESS         IP ADDRESS        REMOTE HOSTNAME&ECHO ===============================================================================
FOR /f "usebackq tokens=1-3" %%a IN (`ARP -a`) DO (
IF "%%a"=="Interface:" (
SET ME=%%b
FOR /f "delims=. tokens=4" %%# IN ("!ME!") DO SET/A MYLAST=%%#
)
SET IP=%%a&SET MAC=%%b&IF "%%c"=="dynamic" (
CALL :GETCOMPUTERNAME !IP! NAME
IF "!IP!"=="!NAME!" SET NAME=Unable to Resolve
FOR /f "delims=. tokens=4" %%# IN ("!IP!") DO (
SET/A LAST=%%#
IF "!LAST:~1,1!"=="" (SET "IP=!IP!  ") ELSE (IF "!LAST:~2,1!"=="" SET "IP=!IP! ")
)
SET "_=  -  "
IF !MYLAST! GTR !LAST! (
ECHO  !MAC!!_!!IP!!_!!NAME!
) ELSE (
IF !SELF! GEQ 1 (
ECHO  !MAC!!_!!IP!!_!!NAME!
) ELSE (
ECHO  !MAC!!_!!ME!!_!!HOST! ^(This Device^)&ECHO  !MAC!!_!!IP!!_!!NAME!&SET/A SELF+=1
)
)
)
)
EXIT /b
:GETHOSTINFO
FOR /f "usebackq" %%# IN (`hostname.exe`) DO (SET HOST=%%#)
PING -n 1 "ifconfig.me" | findstr /r /c:"[0-9] *ms">nul
IF NOT !errorlevel! == 0 (
SET "EXT=No Internet Detected"
) ELSE (
FOR /f "usebackq" %%# IN (`curl -s ifconfig.me`) DO (SET EXT=%%#)
)
FOR /f "usebackq tokens=14" %%# IN (`ipconfig`) DO (IF NOT "%%#"==":" (
SET HOSTIP=%%#
FOR /f "delims=. tokens=4" %%# IN ("!HOSTIP!") DO SET/A HLAST=%%#
IF !HLAST! GEQ 2 SET ISHOST=!HOSTIP!
)
)
EXIT/b
:SCANSUBNETS
CLS&NETSH Interface IPV4 DELETE Neighbors>nul
FOR /f "usebackq tokens=1,2" %%a IN (`ARP -a`) DO (
IF "%%a"=="Interface:" (
SET INTF=%%b
FOR /f "delims=. tokens=1-3" %%a IN ("!INTF!") DO (
SET "SCAN=%%a.%%b.%%c."
SET/A L=1&SET/A P=0&SET/A X=1&SET "MSSG=Sending Packets, Please Wait...."
FOR /L %%# IN (1,1,254) DO (
START /min "" ""CMD.exe /c PING -n 1 -w 200 !SCAN!%%#"">nul
:: No floating point in CMD ;(
SET/A X+=1
IF !X! EQU 2 (CALL :PROGRESS "!MSSG!" 1)
IF !X! EQU 5 (SET/A X=0&CALL :PROGRESS "!MSSG!" 1)
)
)
)
)
SET/A L=1&SET/A P=0&SET "MSSG=Listening, Please Wait.........."
FOR /L %%# IN (1,1,8) DO (
CALL :PROGRESS "!MSSG!" 13
>nul 2>&1 PING 127.0.0.1 -n 2
)
EXIT /b