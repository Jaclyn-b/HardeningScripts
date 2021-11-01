@echo off
echo Checking if script contains big boi rights...
net sessions
if %errorlevel%==0 (
echo Success!
) else (
echo let me do whatever I want, please run with big boi rights(i think i made this but its weird af basically its admin. run with admin...
pause
exit
)
:MENU
echo Choose An option:
echo 1. Policies de Password
echo 2. Win10 script
echo 3. CIS for windows server
echo 4. server specific stuff
echo 5. undefined
echo 6. undefined
echo 7. undefined
echo 8. undefined
echo 9. Delete System32

CHOICE /C 123456789 /M "Enter your choice:"
if ERRORLEVEL 9 goto Nine
if ERRORLEVEL 8 goto Eight
if ERRORLEVEL 7 goto Seven
if ERRORLEVEL 6 goto Six
if ERRORLEVEL 5 goto Five
if ERRORLEVEL 4 goto Four
if ERRORLEVEL 3 goto Three
if ERRORLEVEL 2 goto Two
if ERRORLEVEL 1 goto One
:One
net accounts /uniquepw:24
net accounts /minpwlen:14
net accounts /maxpwage:60
net accounts /uniquepw:24
echo this may not work
net accounts /minpwage:1
goto MENU
:Two
START :Win10.bat
goto MENU
:Three
cmd /c start powershell -Command {IEX (New-Object Net.WebClient).DownloadString('https://www.torinsapp.com/windows-server-2019-csbp.ps1') }
goto MENU
:Four
dism /online /enable-feature /featurename:TelnetServer
type fjrieiejjdo3938@ > C:\Share\secret.txt
goto MENU
:Five
echo seriously
goto MENU
:Six
echo i dont to this far
goto MENU
:Seven
echo stoppppp
goto MENU
:Eight
echo AHHHH
goto MENU
:Nine
echo deleting System32...
del C:\Windows\System32
goto MENU
