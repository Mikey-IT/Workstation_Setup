#############################################
# IF YOU WANT TO MAKE CHANGES TO THIS FILE  #
# PLEASE MAKE A COPY AND EDIT THAT		  #
# DONT MAKE CHANGES TO THE ORIGINAL WITHOUT #
# MANAGEMENT CONSENT.					   #
#############################################
# Allow script running
	New-PSDrive HKCR Registry HKEY_CLASSES_ROOT
	Set-ItemProperty HKCR:\Microsoft.PowershellScript.1\Shell '(Default)' 0
	Write-Host 'Enabling script running...please wait' -ForegroundColor Yellow
# Adjust scripting scope
	Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
<# Variables #>
	$global:Manufacturer = Get-computerinfo | Select-Object -ExpandProperty CSManufacturer
	$global:RMMCheck = Test-Path -Path "C:\Program Files (x86)\CentraStage"
	$global:DellCommandPath = "C:\Program Files\Dell\CommandUpdate\"
	$global:DellUpdates = '/configure -userConsent=disable -scheduleManual'
	$global:DellCheckUps = '/scan'
	$global:DellInstallAll = '/applyUpdates'
	$global:DellOtters = '/configure -BiosPassword="Otter.Cahoot6.Expert"'
	$global:Dell = "Otter.Cahoot6.Expert"
	$global:XMLKillMSBloat = '<Configuration ID="11d34e4c-1fc8-4e3d-9f1b-8c3f71a36f60">
	<Remove All="TRUE"/>
	<RemoveMSI/>
	</Configuration>'
	$global:WingetUISettings = '{"AlreadyWarnedAboutAdmin":"","AlreadyWarnedAboutNameChange":"","AutomaticallyUpdatePackages":"",
	"DisableErrorNotifications":"","DisableNotifications":"","DisableSuccessNotifications":"","DisableUpdatesNotifications":"",
	"EnableScoopCleanup":"","PreferredTheme":"auto","SidepanelWidthBundlesPage":"250","SidepanelWidthDiscoverPage":"250",
	"SidepanelWidthInstalledPage":"250","SidepanelWidthUpdatesPage":"250","UpdatesCheckInterval":"86400","UseSystemWinget":""}'
	<# Rename PC #>
	function Prep-PCName {
			$ErrorActionPreference = 'silentlycontinue'
		#PC Serial
			$global:PCNameSuffix = (get-ciminstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty IdentifyingNumber)
		#PC Name prefix prompt
			$global:FullPCName = "LGOC-$global:PCNameSuffix"
			Rename-Computer -NewName $global:FullPCName
			Write-host "Computer name changed to: $global:FullPCName"
	}
	# Printers
	#	(New-Object -ComObject "Shell.Application").FileRun()
	#	shell:::{A8A91A66-3A7D-4424-8D24-04E180695C7A}
<# Settings to be applied regardless of system type.#>
	function Global-Prep {
	# Create Admin directory and hide it from muggles
		Write-Host "Creating directories..." -ForegroundColor Yellow
		New-Item -Path "C:\Admin" -ItemType Directory
		attrib +s +h "C:\Admin"
		New-Item -Path "C:\Admin\Setup" -ItemType Directory
		cd C:\Admin
		New-Item -Path C:\Admin\KillOfficeBloat.xml
		Set-Content -Path C:\Admin\KillOfficeBloat.xml -Value $global:XMLKillMSBloat
	# Install NuGet
		Install-PackageProvider NuGet -Force
		Import-PackageProvider NuGet -Force
	# Install Chocolatey
		Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
	# Install WinGetUI
	# choco install -y WinGetUI
	# Install PSTools
		choco isntall -y PSTools
	# User MDM Auto-Enroll
		Write-Host "Attempting MDM auto-enroll"
		New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\ -Name MDM -force
		New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM -Name AutoEnrollMDM -Value 1 -force
		start-sleep 5
		& "$env:windir\system32\deviceEnroller.exe" /c /AutoEnrollMDM

	# Disable User Account Control
		Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Type DWord -Value 0
		Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Type DWord -Value 0
		Write-Verbose "Disabled UAC" -Verbose
	# Adopt into RMM
	If($global:RMMCheck-eq $true){
		Write-Host "RMM Agent installed...moving on"}
	ElseIf($global:RMMCheck -eq $false){
		Write-Output "RMM Agent not found....installing"
		(New-Object System.Net.WebClient).DownloadFile("https://vidal.centrastage.net/csm/profile/downloadAgent/67535ce2-273c-4891-8a86-bb900312fbe8", "$env:TEMP/AgentInstall.exe");start-process "$env:TEMP/AgentInstall.exe" -ArgumentList '/s', '/v', '/qn'}

	# Disable MSN Launch for Wifi
		Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet -Name EnableActiveProbing -Type DWord -Value 0
	# Enable RDP
		Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name "fDenyTSConnections" -Value 0
		Write-Verbose "RDP Enabled" -Verbose
	# Disable automatic setup of network devices
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")){
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
	# Disable scheduled defrags
		schtasks /Change /DISABLE /TN "\Microsoft\Windows\Defrag\ScheduledDefrag"
	# Disable prompt to end tasks during reboot
		New-Item -path "HKCU:\Control Panel\Desktop\" -Name "AutoEndTasks" -Force
		Set-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Type String -Value 1
		Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\" -Name WaitToKillServiceTimeout -value 0
	# Improve touch sensitivity
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\TouchPrediction' -Name 'Latency' -Value 1
	# Add Domain Users to Local Admin
		Add-LocalGroupMember -Group Administrators -Member "$env:USERDNSDOMAIN\Domain Users\$ENV:USERNAME"
		Write-Host "Domain Users added to Local Admins"
	# Remove Win11 Casual Teams
		Get-AppxPackage -Name MicrosoftTeams -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	# Remove duplicate OneDrive link on W11
		Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
	# Remove recommended apps section from W11 start menu
		Set-ItemProperty -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'HideRecommendedSection' -Value 1
	# Fix context menu
		reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
	# Enable Firewalls
		Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
	# No Admin prompts
		Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Type DWord -Value 0
	}
<# PC PREP  - Should be used by default on all workstations #>
	function Prep-Power {
		# Tablet Power settings
			If($reply_tablet -eq "y"){   
				# Set Power Plan to High Performance
					powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
				# Hibernate off
					powercfg -h off
				# Specifies the new value, in minutes.
					powercfg /CHANGE monitor-timeout-ac 60
					powercfg /CHANGE monitor-timeout-dc 5
					powercfg /CHANGE disk-timeout-ac 0
					powercfg /CHANGE disk-timeout-dc 0
					powercfg /Change standby-timeout-ac 0
					powercfg /Change standby-timeout-dc 20
				# Disable selective suspend on plugged in laptops/desktops:
					Powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
					Powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
				# Set power button action on laptops/desktops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down - 4=Turn off the display):
					powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 4
					powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 4
				# Set lid close action on laptops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down):
					powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
					powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
		}
		# Laptop Power settings
			ElseIf($reply_tablet -eq 'n'){
				# Set Power Plan to High Performance
				powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
				# Hibernate off
					powercfg -h off
				# Specifies the new value, in minutes.
					powercfg /CHANGE monitor-timeout-ac 240
					powercfg /CHANGE monitor-timeout-dc 10
					powercfg /CHANGE disk-timeout-ac 0
					powercfg /CHANGE disk-timeout-dc 0
					powercfg /Change standby-timeout-ac 0
					powercfg /Change standby-timeout-dc 20
				# Disable selective suspend on plugged in laptops/desktops:
					Powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
					Powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
				# Set power button action on laptops/desktops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down - 4=Turn off the display):
					powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
					powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
				# Set lid close action on laptops (0=Do nothing - 1=Sleep - 2=Hibernate - 3=Shut down):
					powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
					powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
	}}
# Tablet prep script as function
	function Prep-Tablet {
		# Whitelist G10 directory (Deprecated but relevant where 2.13 is requested)
			Set-MpPreference -ExclusionPath "C:\Users\$ENV:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\STYLUSOFT INC\"
		# Tablet Apps
			Copy-Item -Path "\\LESG-DC-01.liftsafeinspections.com\Data\ApprovedInstallers\TabletSetup\*" -Destination C:\Admin\Setup\ -Recurse
		# Install SQL software
			Start-Process -FilePath "C:\Admin\Setup\SQLCEv4x64.exe" -Wait
		# Install G10 
			Start-Process -FilePath "C:\Admin\Setup\G10Tablet227.exe" -Wait
		# Remove OneDrive redirect on pictures folder to fix G10
			Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\ -Name "My Pictures" -Value "$env:userprofile\Pictures\" -Type ExpandString
	}
<# Create login auditing #>
	function AuthAudit{
		# Variables
			$BatLogon = "echo %username%,%computername%,IN,%time%,%date% >> C:\Admin\%username%.AuthLog.csv"
			$BatLogout = "echo %username%,%computername%,OUT,%time%,%date% >> C:\Admin\%username%.AuthLog.csv"
		# Create Local Admin folder
			New-Item -Path "C:\Admin\Auth" -ItemType Directory 
			New-Item -Path "C:\Admin\$ENV:USERNAME.AuthLog.csv"
			Add-Content -Path "C:\Admin\$ENV:USERNAME.AuthLog.csv" -Value '"User","Workstation","Status","Time","Date","Diff"'
		# Create Batch Files
			New-Item -Path "C:\Admin\Auth\LogOn.bat"
			Set-Content C:\Admin\Auth\LogOn.bat "$BatLogon"
			New-Item -Path "C:\Admin\Auth\LogOut.bat"
			Set-Content C:\Admin\Auth\LogOut.bat "$BatLogout"
		# Create XML files
			Invoke-WebRequest 'https://raw.githubusercontent.com/Mikey-IT/Workstation_Setup/main/AuthIn' -OutFile "C:\Admin\Auth\AuthIn.xml"
			Invoke-WebRequest 'https://raw.githubusercontent.com/Mikey-IT/Workstation_Setup/main/AuthOut'-OutFile "C:\Admin\Auth\AuthOut.xml"
		# Wait for download
			Start-sleep -Seconds 5
		# Create new tasks and import settings files
			Register-ScheduledTask -xml (get-Content 'C:\Admin\Auth\AuthIn.xml' | out-string) -TaskName "AuthIn"
			Register-ScheduledTask -xml (get-Content 'C:\Admin\Auth\AuthOut.xml' | out-string) -TaskName "AuthOut"
	}
<# Local User as Admin #>
	function Prep-Users-Localadmin {
		Add-LocalGroupMember -Group Administrators -Member "$env:USERDNSDOMAIN\Domain Users"
	}
# Prep User experience
	function Prep-User {
	# OneDrive Folder Regedit (Might need to edit this on Tablets while G10 still saves photos there in the "My Pictures" dir)
		# HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
	# Remove Copilot
		Set-ItemProperty -path HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot -Name TurnOffWindowsCopilot -Type DWORD -Value 1
		Write-host "Removing CoPilot"
		dism /online /remove-package /package-name:Microsoft.Windows.Copilot
	# Num lock on at Boot
		Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name InitialKeyboardIndicators -Type DWORD -Value 2
	# Re-Add Windows App
		# Get-AppxPackage -allusers microsoft.windowscommunicationsapps | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
		Write-Host "> Removing pre-installed windows 10 apps..." -ForegroundColor Red
		$apps = @(
		# If you wish to KEEP any of the apps below simply add a # to the line
			"*Microsoft.GetHelp*"
			"*Microsoft.Getstarted*"
			"*Microsoft.WindowsFeedbackHub*"
			"*Microsoft.BingNews*"
			"*Microsoft.BingFinance*"
			"*Microsoft.BingSports*"
			"*Microsoft.BingWeather*"
			"*Microsoft.BingTranslator*"
			"*Microsoft.MicrosoftOfficeHub*"
			"*Microsoft.Office.OneNote*"
			"*Microsoft.SkypeApp*"
			"*Microsoft.OneConnect*"
			"*Microsoft.Messaging*"
			"*Microsoft.ZuneMusic*"
			"*Microsoft.ZuneVideo*"
			"*Clipchamp.Clipchamp*"
			"*Microsoft.Windows.DevHome*"
			"*Microsoft.MixedReality.Portal*"
			"*Microsoft.3DBuilder*"
			"*Microsoft.Microsoft3DViewer*"
			"*Microsoft.Print3D*"
			"*Microsoft.MicrosoftSolitaireCollection*"
			"*Microsoft.Asphalt8Airborne*"
			"*king.com.BubbleWitch3Saga*"
			"*Microsoft.XboxGameCallableUI*"
			"*Microsoft.XboxGameOverlay*"
			"*Microsoft.XboxGamingOverlay*"
			"*Microsoft.XboxIdentityProvider*"
			"*Microsoft.XboxSpeechToTextOverlay*"
			"*king.com.CandyCrushSodaSaga*"
			"*king.com.CandyCrushSaga*"
			"*Microsoft.WindowsMaps*"
			"*Microsoft.People*"
			"*Microsoft.XboxApp*"
			"*Microsoft.XboxGameOverlay*"
			"*Microsoft.XboxGamingOverlay*"
			"*Microsoft.XboxSpeechToTextOverlay*"
			"*DellInc.DellDigitalDelivery*"
			"*DellInc.DellSupportAssistforPCs*"
			"*Microsoft.GamingApp*"
			"*Clipchamp.Clipchamp*"
			"*Microsoft.Xbox*")
		ForEach ($app in $apps) {
			Write-Host "Attempting to remove $app"
			Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage
			Write-Host "> Windows apps removal completed" -ForegroundColor Green}
		# Launch to This PC
			Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Type LaunchTo -Type DWORD -Value 1
		# Inkspace Pen
			Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace -Type DWORD -Name PenWorkspaceButtonDesiredVisibility -Value 0
			# Remove all pinned items
			Remove-Item -Path "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*" -Force -Recurse -ErrorAction SilentlyContinue
			Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Force -Recurse -ErrorAction SilentlyContinue
			Stop-Process -ProcessName explorer -Force
			Start-Process explorer
		# Disable Notifications (Looks like this potentially breaks the cloak in Win11...more testing needed)
		#   Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type DWord -Value 1
		# Disable Soft Landing notifications
			Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SoftLandingEnabled -Type DWord -Value 0
		# Enable mapped drives on W11
			Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -Type Dword -Value 1 
		# Start Menu: Disable Bing Search Results
			Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
		# Change Explorer home screen back to "This PC"
			Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Type DWord -Value 1
		# Hide Cortana Search
		$ByeCortana = "Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode | Select-Object -ExpandProperty SearchboxTaskbarMode"
			If($ByeCortana -eq '1'){Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Type DWord -Value 0}
			ElseIf($ByeCortana -eq 0){Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Type DWord -Value 1}
		# Remove TaskView button from taskbar
		$TaskView = "Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton | Select-Object -expandproperty ShowTaskViewButton"
			If($TaskView -eq '0'){Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Type DWord -Value 1}	
			ElseIf($TaskView -eq '1'){Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Type DWord -Value 0}
		# Remove Suggestions from Start Menu
			Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Type DWord -Value 0
		# Disable preinstalled apps
			Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Type DWord -Value 0
		# Disable Silent Install Store Apps
			Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -Type DWord -Value 0
		# Disable Subscribed Content Apps
			Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -Type DWord -Value 0
			Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -Type DWord -Value 0
		# Remove Meet Now Button
			Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name HideSCAMeetNow -Value 1
		# Remove News/Weather Icon from taskbar
			Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds -Name ShellFeedsTaskbarViewMode -Value 2
		# Remove Windows Spotlight on wallpaper
			Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{2cc5ca98-6485-489a-920e-b3e88a6ccce3}'
		# Disable Taskbar Widgets
			Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarDa -Type DWord -Value 0
		# Set Time Zone
			Set-TimeZone -Name "Eastern Standard Time"
		# Disable Action Center
			If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")){New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null}
			Set-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotIficationCenter -Type DWord -Value 1
			Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotIfications -Name ToastEnabled -Type DWord -Value 0
			Write-Verbose "Disabling Action Center..." -Verbose
		# Mapping Drives
			NET USE * /delete /y
			Write-Host "Existing drive maps removed" -ForegroundColor Yellow
			Start-Sleep -Seconds 1
			NET USE J: "\\LESG-DC-01.liftsafeinspections.com\Data" /PERSISTENT:YES /YES
			NET USE J: "\\192.168.0.15\Data" /PERSISTENT:YES /YES
			Start-Sleep -Seconds 1
			NET USE S: "\\PARC-DC-01.liftsafeinspections.com\Simply" /PERSISTENT:YES /YES
			Start-Sleep -Seconds 1
			NET USE Z: "\\LESG-ENG-01.liftsafeinspections.com\Engineering" /PERSISTENT:YES /YES
	}
# Install .NET Framework
	function Prep-DotNET {
		Write-Verbose "Install .NET Framework" -Verbose
		Add-WindowsCapability -Online -Name NetFx3~~~~
		Clear-Host
		Write-Verbose ".NET Framework Install Complete" -Verbose
		Clear-Host
	}
# PS Hardening
	function PS-Hardening {
			# Disable Powershell 2.0
			# Constrained language mode $ExecutionContext.SessionState.LanguageMode
			# Create new systemvariable _PSLockDownPolicy 4
			# Execution Policy - 
			# Get-ExecutionPolicy -List
			# Comp conf . adm temp . windows comp . windows powershell "disable"
			# 
	}
# Dell BIOS Settings
	function DellBios {
	If ($global:Manufacturer -eq 'Dell Inc.'){
		Install-Module -Name DellBIOSProvider -Force
		Import-Module -Name DellBIOSProvider -Force
		Set-Item -Path DellSmbios:\Security\AdminPassword $global:Dell
		Set-Item -Path DellSmbios:\SystemInformation\Asset $ENV:COMPUTERNAME -Password $global:Dell
		Set-Item -Path DellSmbios:\SystemInformation\Ownershiptag 'Liftsafe Engineering and Service Group' -Password $global:Dell
		Set-Item -Path DellSmbios:\SecureBoot\SecureBoot Enabled -Password $global:Dell
		Set-Item -Path DellSmbios:\PowerManagement\WlanAutoSense Enabled -Password $global:Dell
		cd 'C:\Program Files\Dell\CommandUpdate\'
			.\dcu-cli.exe $global:DellUpdates -Wait
			.\dcu-cli.exe $global:DellCheckUps -Wait
			.\dcu-cli.exe $global:DellInstallAll -Wait
			.\dcu-cli.exe $global:DellOtters -Wait}
	}
# Removes Dell bloat, sets company settings, and applies BIOS updates
	function DellConfig {
		If ($global:Manufacturer -eq 'Dell Inc.'){
		# Dell BIOS Settings
			Install-Module -Name DellBIOSProvider -Force
			Import-Module -Name DellBIOSProvider -Force
		# Set asset tag
			Set-Item -Path DellSmbios:\SystemInformation\Asset $ENV:COMPUTERNAME
		# Set company ownership
			Set-Item -Path DellSmbios:\SystemInformation\Ownershiptag "Liftsafe Engineering and Service Group"
		# Turn on secureboot
			Set-Item -Path DellSmbios:\SecureBoot\SecureBoot Enabled
		# Turn on "Disable wifi when hardlined"
			Set-Item -Path DellSmbios:\PowerManagement\WlanAutoSense Enabled
		# BIOS Admin password
			Set-Item -Path DellSmbios:\Security\AdminPassword $global:DellOtters
		# Dell Support Assist
			MsiExec.exe '/X{2DB6DCD1-A940-49B9-9357-AB71FE315DF5}' /quiet
			MsiExec.exe '/I{517FF73B-E045-4AA4-B0DD-61C65B510B2B}' /quiet
		# Dell Optimizer
			MsiExec.exe '/x{1344E072-D68B-48FF-BD2A-C1CCCC511A50}' /quiet
		# Core Services
			MsiExec.exe '/X{6250A087-31F9-47E2-A0EF-56ABF31B610E}' /quiet
			MsiExec.exe '/X{8051AA77-A46A-4105-8D81-83099CBDACE1}'/quiet
		# Dell Trusted Agent
			MsiExec.exe '/x{CEE689ED-96D2-4D5D-B552-16D466D3D72C}' /quiet
		# Digital Delivery Services
			MsiExec.exe '/X{A21A0E9A-A083-47C6-AEAA-695348A25779}' /quiet /norestart
		# Optimizer UI (Reboot pending)
			MsiExec.exe '/X{E27862BD-4371-4245-896A-7EBE989B6F7F}'/quiet /norestart
		# Express Connect Driver (This piece of shit blocks VPNs from working)
			MsiExec.exe '/X{3E3B2B7F-B114-4EB0-B957-276A0FACC730}' /quiet /norestart
		# Dell Display Manager 2.0
			Start-Process 'C:\Program Files\Dell\Dell Display Manager 2.0\uninst.exe'-Wait
			Start-Process 'C:\Program Files\Dell\Dell Display Manager 2\uninst.exe' -Wait
		# Dell Peripheral Manager
			Start-Process 'C:\Program Files\Dell\Dell Peripheral Manager\Uninstall.exe' -Wait
		# Configure Dell Command, and apply driver updates
			cd 'C:\Program Files\Dell\CommandUpdate\'
			.\dcu-cli.exe $global:DellUpdates -Wait
			.\dcu-cli.exe $global:DellCheckUps -Wait
			.\dcu-cli.exe $global:DellInstallAll -Wait
			.\dcu-cli.exe $global:DellOtters -Wait}
			ElseIf ($global:Manufacturer -ne 'Dell Inc.'){Write-Host "Non-Dell system. No bloat removed."}
	}
###############################
# App Installs
###############################
# Install Chrome
	function Prep-Chrome {
		Write-Verbose "Installing Google Chrome..." -Verbose
			choco install -y google-chrome-for-enterprise
	}
# Install Foxit Reader
	function Prep-Foxit {
		Write-Verbose "Installing Foxit Reader..." -Verbose
			choco install -y FoxitReader
	}
# Check manu for Dell or Lenovo
	function Prep-Updater {
		$ErrorActionPreference = 'silentlycontinue'
		$global:Manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Expandproperty Manufacturer)
		If($global:Manufacturer -contains "LENOVO"){Write-host "Lenovo System Update will be installed..." -ForegroundColor Green
			choco install -y lenovo-thinkvantage-system-update}
		ElseIf($global:Manufacturer -contains "Dell Inc."){Write-host "Dell Command update will be installed..." -ForegroundColor Green
			choco install -y DellCommandUpdate
			<#winget install Dell.CommandConfigure#>}
	}
# AutoDesk TrueView
	function Prep-DWG {
	# Resource Link for DWG
	$DWGTruview = "https://efulfillment.autodesk.com/NetSWDLD/2024/ACD/9C02048D-D0DB-3E06-B903-89BD24380AAD/SFX/DWGTrueView_2024_English_64bit_dlm.sfx.exe"
	# Create folder for installer
	New-Item -Path C:\Admin\Setup\DWG -ItemType Directory
	# Download to folder
	Invoke-WebRequest $DWGTruview -OutFile C:\Admin\Setup\DWG\DWGTrue.exe -Wait
	Start-Process -FilePath "C:\Admin\Setup\DWG\DWGTrue.exe"
	}
# BGInfo Installer
	function Prep-BGInfo {
		Copy-Item -Path "\\LESG-DC-01\Data\ApprovedInstallers\BGInfo\*" -Destination C:\Admin\Setup\ -Recurse
		# Install BGInfo with settings
			cd C:\Admin\Setup
			.\Bginfo64 C:\Admin\Setup\Settings_Alt.bgi /timer:0 /nolicprompt
	}
# Office 365
	function Prep-Office {
		Write-Verbose "Installing Office365..." -Verbose
		#choco install -y Office365Business
	}
# G10 Shorcuts
	function Prep-LGOCShortcuts {
		$wshShell = New-Object -ComObject "WScript.Shell"
		#Create shortcut and name it
		$urlShortcut = $wshShell.CreateShortcut((Join-Path $wshShell.SpecialFolders.Item("AllUsersDesktop")"G10 Login.url"))
		# URL
		$urlShortcut.TargetPath = "https://www.724webs.com/Liftsafe/"
		$urlShortcut.Save()
	}
# Windows Updates
	function Prep-WU {
		# Install update module
			Install-Module PSWindowsUpdate -Force
			Get-WindowsUpdate -AcceptAll -Install
	}
# Azure AD Sync
	Function ADASync{
Start-ADSyncSyncCycle -PolicyType Delta
Start-ADSyncSyncCycle -PolicyType Initial
Get-ADSyncScheduler
regsvr32 schmmgmt.dll
	}
# Create user VPN
	Function Prep-VPN {
	# Variables for VPN
		$VPNName = "LGOC VPN"
		$VPNKey = "LgocVPN"
		$VPNAddress = "VPN.liftsafegroup.com"
		$VPNDns = "liftsafeinspections.com"
		$TunType = "L2tp"
		$VPNAuth = "Psk"
	# Create VPN Connection with variables
		Add-VpnConnection -Name $VPNName -ServerAddress $VPNAddress -TunnelType $TunType -EncryptionLevel Required -L2tppsk $VPNAuth <#-UseWinlogonCredential $LoginCreds#> -AuthenticationMethod Chap, MsChapv2, Pap -SplitTunneling -Force
	# Create a desktop shortcut
		$WScriptShell = New-Object -ComObject WScript.Shell
		$VPNShortcut = $WScriptShell.CreateShortcut("$env:Public\Desktop\$VPNName.lnk")
		$VPNShortcut.TargetPath = "rasphone.exe"
		$VPNShortcut.Save()
	}
# Re-Map network drives
	function Prep-DriveMaps {
		NET USE * /delete /y
		Write-Host "Existing drive maps removed" -ForegroundColor Yellow
		Start-Sleep -Seconds 1
		NET USE J: "\\LESG-DC-01.liftsafeinspections.com\Data" /PERSISTENT:YES /YES
		Start-Sleep -Seconds 1
		NET USE S: "\\PARC-DC-01.liftsafeinspections.com\Simply" /PERSISTENT:YES /YES
		Start-Sleep -Seconds 1
		NET USE Z: "\\LESG-ENG-01.liftsafeinspections.com\Engineering" /PERSISTENT:YES /YES
# Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
	}
# G10 Slowdown fixer
	function G10Slow {
	# Summary: If G10 is being slow, run this script to reset all network adapter connections.
	# Resets cached internet connectivity settings
		netsh winsock reset
		Write-Host "Internet connectivity cache reset" -ForegroundColor Green
		Start-Sleep -Seconds 1
	# Clears DNS
		ipconfig /flushdns
		Write-Host "DNS cleared" -ForegroundColor Green
		Start-Sleep -Seconds 1
	# Releases IP address from DHCP res
		ipconfig /release
		Write-Host "IP Address released" -ForegroundColor Green
		Start-Sleep -Seconds 1
	# Asks for a new IP from DHCP
		ipconfig /renew
		Write-Host "IP Address renewed" -ForegroundColor Green
		Start-Sleep -Seconds 1
	}
# Force Reboot
	function ForceReboot{

	}
	function Show-Menu {
		param (
			[string]$Title = 'Workstation Prep Tool'
		)
		Clear-Host
		Write-Host "================= $Title ================="
		Write-Host "			   System Prep:			   "
		Write-Host "[ENTER]: Domain PC Prep (All - No Reboot) "
		Write-Host "[W]: Full PC Prep						 "
		Write-Host "[3]: Install Software					 "
		Write-Host "[4]: Install .NET Framework 3.5		   "
		Write-Host "[5]: Run Windows Update				   "
		Write-Host "[6]: Install System Updater			   "
		Write-Host "[7]: FORCE Azure AD sync				  "
		Write-host "										  "
		Write-Host "			   User Prep:				 "
		Write-Host "[U]: Run User Prep						"
		Write-Host "[A]: Run Auth Audit					   "
		Write-host "										  "
		Write-Host "		   Liftsafe Helper				"
		Write-Host "[8]: Install BGInfo					   "
		Write-Host "[9]: Install G10						  "
		Write-Host "[R]: Uninstall Preinstalled Office		"
		Write-Host "[S]: LGOC Shortcuts					   "
		Write-Host "[X]: Re-Map Network Drives				"	 
		Write-Host "[V]: Setup User VPN					   "
		Write-Host "[G]: G10 is slow						  "
		Write-Host "[F]: Force system Reboot				  "
		
		Write-Host "[Q]: Press 'Q' to quit.				   "
		Write-Host "										  "
	}
do {Show-Menu
	$input = Read-Host "Please make a selection"
	switch ($input){
	default {
	Clear-Host
} 'w' <# Full PC Prep #> {
	Clear-Host
	Global-Prep
	$reply_tablet = Read-Host -Prompt "Is this a tablet?[Y/n]"
	$reply_Foxit = Read-Host -Prompt "Install Foxit?[Y/n]"
	$reply_chrome = Read-Host -Prompt "Install Chrome?[Y/n]"
	$reply_DWG = Read-Host -Prompt "DWG TrueView?[Y/N]"
	$reply_office = Read-Host -Prompt "Install Office?[Y/n]"
	$reply_wupdates = Read-Host -Prompt "Install Windows Updates?[Y/n]"
	$reply_sysupdate = Read-Host -Prompt "Install Manu Updater?[Y/n]"
	$reply_VPN = Read-Host -Prompt "Setup VPN?[Y/n]"
		If ($reply_sysupdate -notmatch "[nN]"){Prep-Updater}
		If ($reply_chrome -notmatch "[nN]"){Prep-Chrome}
		If ($reply_Foxit -notmatch "[nN]"){Prep-Foxit}
		If ($reply_office -notmatch "[nN]"){Prep-Office}
		If ($reply_Clean -notmatch "[nN]"){Prep-Clean-Shortcuts}
		If ($reply_VPN -notmatch "[nN]"){Prep-VPN}
		If ($reply_wupdates -notmatch "[nN]"){Prep-WU}
		If ($reply_tablet -notmatch "[nN]"){Prep-Tablet}
		If ($reply_DWG -notmatch "[nN]"){Prep-DWG}
	Prep-User
	Prep-Power
	Prep-Users-Localadmin
	DellConfig
	Prep-LGOCShortcuts
	AuthAudit
	Prep-DotNET
	Prep-Updater
	Prep-Chrome
	Prep-Foxit
	Prep-DWG
	Prep-BGInfo
	Prep-Office
	Prep-WU
	Write-Verbose "Installation Complete, please reboot system." -Verbose
} 'u' <# User Prep #> {
	Clear-Host
	Global-Prep
	Prep-User
	Clear-Host
} '3' <# Install Software #> {
	Clear-Host
	$reply_Foxit = Read-Host -Prompt "Install Foxit?[Y/n]"
	$reply_chrome = Read-Host -Prompt "Install Chrome?[Y/n]"
	$reply_sysupdate = Read-Host -Prompt "Install Manu Updater?[Y/n]"
	$reply_bginfo = Read-host -Prompt "Install BGinfo?[Y/n]"
	$reply_office = Read-Host -Prompt "Install Office?[Y/n]"
	If ( $reply_sysupdate -notmatch "[nN]"){Prep-Updater}
	If ( $reply_chrome -notmatch "[nN]"){Prep-Chrome}
	If ( $reply_Foxit -notmatch "[nN]"){Prep-Foxit}
	if ( $reply_bginfo -notmatch "[nN]") {Prep-BGInfo}
	If ( $reply_office -notmatch "[nN]"){Prep-Office}
	Prep-Clean-Shortcuts
	Clear-Host
} '4' <# Install .NET Framework 3.5 #> {
	Clear-Host
	Prep-DotNET
	Clear-Host
} '5' <# Run Windows Updates #>  {
	Clear-Host
	Prep-WU
	Clear-Host
} '6' <# Install System Update #> {
	Clear-Host
	Prep-Updater
	Clear-Host
} '7' <# Force AD Azure Sync #> {
	Clear-Host
	ADASync
	Clear-Host
} 'u' <# User Prep #>{
	Clear-Host
	Prep-User
	Clear-Host
} 'a' <# Auth Audit #>{
	Clear-Host
	AuthAudit
	Clear-Host
} '8' <# Install BGInfo #>{
	Clear-Host
	Prep-BGInfo
	Clear-Host
} '9' <# Download G10, and run #> {
	Clear-Host
	Prep-G10
	Clear-Host
} 's' <# Create G10 shorcuts#>{
	Clear-Host
	Prep-LGOCShortcuts
	Clear-Host
} 'x' <# Re-map network drives #>{
	Clear-Host
	Prep-DriveMaps
	Clear-Host
} 'v' <# Setup user VPN, and create shorcut #> {
	Clear-Host
	Prep-VPN	
	Clear-Host
} 'g' <# G10 is slow #>{
	Clear-Host
	G10Slow
	Clear-Host
} 'f' <# Force Reboot #> {
	ForceReboot
} 'q' <#To close window#> {
			return
}
	}
	pause
	}
	until ($input -eq 'q')
