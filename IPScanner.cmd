@ECHO OFF&SETLOCAL ENABLEDELAYEDEXPANSION
SET "TitleName=IP Scanner"
TASKLIST /V /NH /FI "imagename eq cmd.exe"|FIND /I /C "!TitleName!">nul
IF NOT !errorlevel!==1 (ECHO ERROR:&ECHO IP Scanner is already open) |MSG * & EXIT /b
TITLE !TitleName!
>nul 2>&1 reg add hkcu\software\classes\.IPscanner\shell\runas\command /f /ve /d "cmd /x /d /r set \"f0=%%2\"& call \"%%2\" %%3"& set _= %*
>nul 2>&1 fltmc|| if "%f0%" neq "%~f0" (cd.>"%ProgramData%\runas.IPscanner" & start "%~n0" /high "%ProgramData%\runas.IPscanner" "%~f0" "%_:"=""%" & exit /b)
>nul 2>&1 reg delete hkcu\software\classes\.IPscanner\ /f &>nul 2>&1 del %ProgramData%\runas.IPscanner /f /q
>nul 2>&1 netsh advfirewall firewall set rule group=”Network Discovery” new enable=Yes
:LOAD
CALL :GETHOSTINFO
CALL :SCANSUBNETS
CALL :LISTMACHINES
ECHO.&ECHO Press any key to refresh, (X) to Exit
SET "KEY="&FOR /f "delims=" %%K IN ('2^> nul XCOPY /L /W /I "%~f0" "%TEMP%"') DO IF NOT DEFINED KEY SET "KEY=%%K"
IF /I "!KEY:~-1!"=="X" GOTO :EOF
GOTO :LOAD
:LISTMACHINES
SET/A DONE=0
CLS&ECHO ExternalIP: !EXT!&ECHO InternalIP: !ISHOST!&ECHO Hostname  : !HOST!
ECHO.&ECHO   IP ADDRESS    -   REMOTE HOSTNAME&ECHO ========================================================
FOR /f "usebackq tokens=1-3" %%a IN (`ARP -a`) DO (
IF "%%a"=="Interface:" (
SET THIS=%%b
FOR /f "delims=. tokens=1-4" %%a IN ("!THIS!") DO SET/A MYLAST=%%d
)
SET IP=%%a&IF "%%c"=="dynamic" (
CALL :GETCOMPUTERNAME !IP! NAME
IF "!IP!"=="!NAME!" SET NAME=Unable to Resolve Remote HostName
FOR /f "delims=. tokens=1-4" %%a IN ("!IP!") DO (
SET/A LAST=%%d
IF "!LAST:~1,1!"=="" (SET "IP=%%a.%%b.%%c.!LAST!  ") ELSE (IF "!LAST:~2,1!"=="" SET "IP=%%a.%%b.%%c.!LAST! ")
)
IF !MYLAST! GTR !LAST! (
ECHO  !IP!  -  !NAME!
) ELSE (
IF !DONE! GEQ 1 (
ECHO  !IP!  -  !NAME!
) ELSE (
ECHO  !THIS!  -  !HOST! ^(This Device^)&ECHO  !IP!  -  !NAME!&SET/A DONE+=1
)
)
)
)
EXIT /b
:GETHOSTINFO
FOR /f "usebackq" %%# IN (`hostname.exe`) DO (SET HOST=%%#)
FOR /f "usebackq" %%# IN (`curl -s ifconfig.me`) DO (SET EXT=%%#)
FOR /f "usebackq tokens=14" %%# IN (`ipconfig`) DO (IF NOT "%%#"==":" (
SET HOSTIP=%%#
FOR /f "delims=. tokens=1-4" %%a IN ("!HOSTIP!") DO SET/A HLAST=%%d
IF !HLAST! GEQ 2 SET ISHOST=!HOSTIP!
)
)
EXIT/b
:GETCOMPUTERNAME
FOR /f "usebackq tokens=2" %%a IN (`PING -a %1 -n 1 -w 200`) DO (SET %2=%%a)&EXIT /b
EXIT /b
:SCANSUBNETS
CLS&NETSH Interface IPV4 DELETE Neighbors>nul
FOR /F %%a IN ('COPY/Z "%~dpf0" nul')DO FOR /F skip^=4 %%b IN ('ECHO;PROMPT;$H^|CMD')DO SET "BS=%%b"&SET "CR=%%a"
SET "_spc=                    "&SET "_bar=####################"
FOR /f "usebackq tokens=1,2" %%a IN (`ARP -a`) DO (
IF "%%a"=="Interface:" (
SET INTF=%%b
FOR /f "delims=. tokens=1-4" %%a IN ("!INTF!") DO (
SET "SCAN=%%a.%%b.%%c."
SET/A L=1&SET/A P=0&SET/A count=1
FOR /L %%i IN (1,1,254) DO (
START /min "" ""CMD.exe /c PING -n 1 -w 200 !SCAN!%%i"">nul
:: No floating point in CMD ;(
SET/A count+=1
IF !count! EQU 2 (CALL :PROGRESS "Sending Packets, Please Wait...." 1)
IF !count! EQU 5 (SET/A count=0&CALL :PROGRESS "Sending Packets, Please Wait...." 1)
)
)
)
)
CLS&SET/A L=1&SET/A P=0
FOR /L %%i IN (1,1,8) DO (
CALL :PROGRESS "Listening, Please Wait.........." 13
>nul 2>&1 PING 127.0.0.1 -n 2
)
EXIT /b
:PROGRESS
SET/A P+=%2
IF %P% GEQ 5 SET/A L=(%P%/5)+1&IF %P% GEQ 100 SET/A P=100
SET/P "=!CR!!BS!!CR![!_bar:~0,%L%!!BS!!_spc:~%L%!]%~1 [%%%P%] "<nul
EXIT /b
