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
echo 2. processes
echo 3. CIS for windows server
echo 4. Find contraband
echo 5. Disable Remote Desktop(letting bad people in our computer >:( )
echo 6. GIve your pc the good stuff(auto-updates)
echo 7. Disable Weak services
echo 8. i look for evil stuff
echo 9. rootkit go boom

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
goto MENU
:Three
cmd /c start powershell -Command {IEX (New-Object Net.WebClient).DownloadString('https://www.torinsapp.com/scripts/passwordpolicies.ps1') }
goto MENU
