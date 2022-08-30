# Check if Admin dir exists
$global:Admindir = Test-Path -Path C:\Admin
if ($global:Admindir -eq $true){
    Write-host "Admin path exists, proceeding." -ForegroundColor Green}
elseif ($global:Admindir -eq $false) {Write-Host "Admin path doesn't exist, creating"
    New-Item -ItemType Directory "C:\Admin"}

New-PSDrive HKCR Registry HKEY_CLASSES_ROOT
Set-ItemProperty HKCR:\Microsoft.PowershellScript.1\Shell '(Default)' 0
Write-Host 'Enabling script running...please wait' -ForegroundColor Yellow
Start-Sleep 3

Write-Host "System Prep selector (P)ersonal, (C)orporate, (B)oth:"
$global:Preptype = Read-host -Prompt "Input selection"

Function SysPrep(){
# Prep Script for Corporate worsktations
# Download from raw-text Github link
Write-Host 'Updating script...please wait' -ForegroundColor Yellow
Invoke-WebRequest -uri https://raw.githubusercontent.com/Mikey-IT/Workstation_Setup/main/WorkstationPrep.ps1 -OutFile C:\Admin\Workstation-Prep.Ps1
Invoke-WebRequest -uri https://github.com/Mikey-IT/Workstation_Setup/blob/main/Bginfo64.exe -OutFile C:\Admin\BGInfo.exe

# Overwrite existing file in C:\Admin
Write-Host 'Update complete - launch workstation prep' -ForegroundColor Green
Start-Sleep -Seconds 2
Invoke-Item -Path C:\Admin\Workstation-Prep.Ps1
Start-Sleep -Seconds 2
}

function Debloat(){
# Debloat & Sys-Prep for home computers
Write-Host 'Updating script...please wait' -ForegroundColor Yellow
Invoke-WebRequest -uri https://raw.githubusercontent.com/ChrisTitusTech/winutil/main/winutil.ps1 -OutFile C:\Admin\winutil.Ps1
Write-host "Downloading W10 Debloat tool" -ForegroundColor Green
Start-Sleep -seconds 2
Invoke-Item -Path C:\Admin\winutil.Ps1
Start-Sleep -seconds 2
}

function Both(){
    Write-host "Downloading W10 Debloat tool" -ForegroundColor Green
    Invoke-WebRequest -uri https://raw.githubusercontent.com/ChrisTitusTech/winutil/main/winutil.ps1 -OutFile C:\Admin\winutil.Ps1
    Write-Host 'Downloading prep script...please wait' -ForegroundColor Yellow
    Invoke-WebRequest -uri https://raw.githubusercontent.com/Mikey-IT/Workstation_Setup/main/WorkstationPrep.ps1 -OutFile C:\Admin\Workstation-Prep.Ps1
    Invoke-Item -Path C:\Admin
    Start-Sleep -Seconds 2
}

# (P)ersonal selected
If($global:Preptype -eq 'P'){
    Debloat}
# (C)orporate selected
ElseIf ($global:Preptype -eq 'C'){
    SysPrep}
# (B)oth selected
ElseIf ($global:Preptype -eq 'B'){
    Both}
# No selection made
Else{Write-Host "No selection was made, try again."
     Start-sleep -Seconds 3
}
# Once process is completed, close the window
Stop-process -Id $PID
