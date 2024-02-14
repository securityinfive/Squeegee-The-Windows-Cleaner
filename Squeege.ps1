#########################################
# Author  : Drew Koenig
# Tool    : Squeege (The Windows Cleaner)
# Version : 1.0
# Contact : securityinfive@binaryblogger.com
# Twitter : @SecurityInFive
# Website : https://securityinfive.com
# GIT     : <insert location>
#########################################

Clear-host

#=====================
#    Set Variables
#====================
$CurrentPath = Get-Location | Select-Object | ForEach-Object{$_.ProviderPath}
$CurrentDateTime = Get-Date
$CurrentUserName = [System.Environment]::UserName
$ReportName = "SqueegeReport.txt"
$BannerColor = "Red"
$DataColor = "Yellow"
$TextColor = "White"
$AppInfoColor = "Green"
$ErrorActionPreference = "Stop"

$Banner = "#######################################################################
_______  _______           _______  _______  _______  _______ 
(  ____ \(  ___  )|\     /|(  ____ \(  ____ \(  ____ \(  ____ \
| (    \/| (   ) || )   ( || (    \/| (    \/| (    \/| (    \/
| (_____ | |   | || |   | || (__    | (__    | |      | (__    
(_____  )| |   | || |   | ||  __)   |  __)   | | ____ |  __)   
      ) || | /\| || |   | || (      | (      | | \_  )| (      
/\____) || (_\ \ || (___) || (____/\| (____/\| (___) || (____/\
\_______)(____\/_)(_______)(_______/(_______/(_______)(_______/

                   Windows Cleaner 1.0
#######################################################################
Author: Drew Koenig
Contact: securityinfive@binaryblogger.com
GIT: https://github.com/<insert>
Web: https://www.securityinfive.com
Twitter: @SecurityInFive
#######################################################################"

Write-Host -ForegroundColor $BannerColor $Banner
Add-Content -Path $CurrentPath"\"$ReportName -Value "`r`n$Banner"

#Invoke-RestMethod -uri "https://artii.herokuapp.com/make?text=SQUEEGE&font=epic" -DisableKeepAlive

#=====================
#    Loader
#=====================
Write-Host "Welcome To Squeege."
Write-Host -ForegroundColor $AppInfoColor "[+]  SQUEEGE is starting"
Start-Sleep -s 1
Write-Host -ForegroundColor $TextColor "[+]  The report will be saved to : " -NoNewline
Write-Host -ForegroundColor $DataColor $CurrentPath"\"$ReportName
Write-Host -ForegroundColor $TextColor "[+]  Running User                : " -NoNewline
Write-Host -ForegroundColor $DataColor $CurrentUserName 
Write-Host -ForegroundColor $TextColor "[+]  Scans Starting              : " -NoNewline
Write-Host -ForegroundColor $DataColor $CurrentDateTime
Write-Host ""
Add-Content -Path $CurrentPath"\"$ReportName -Value "`r`n SQUEEGE Scan Started on $CurrentDateTime."
#==================================
#   Get System Info
#==================================
Write-Host -ForegroundColor $AppInfoColor "##############################"
Write-Host -ForegroundColor $AppInfoColor " Gathering System Information"
Write-Host -ForegroundColor $AppInfoColor "##############################"
Add-Content -Path $CurrentPath"\"$ReportName -Value "##############################"
Add-Content -Path $CurrentPath"\"$ReportName -Value " Gathering System Information"
Add-Content -Path $CurrentPath"\"$ReportName -Value "##############################"
Start-Sleep -s 1

$ComData = Get-ComputerInfo
Write-Host -ForegroundColor $TextColor "[+]  Logged On User              : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.CsUsername
Add-Content -Path $CurrentPath"\"$ReportName -Value "Logged On User      : $ComData.CsUsername"

Write-Host -ForegroundColor $TextColor "[+]  Logon Server                : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.LogonServer
Add-Content -Path $CurrentPath"\"$ReportName -Value "Logon Server        : $ComData.LogonServer"

Write-Host -ForegroundColor $TextColor "[+]  Computer Name               : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.CsName
Add-Content -Path $CurrentPath"\"$ReportName -Value "Computer Name            : $ComData.CsName"

Write-Host -ForegroundColor $TextColor "[+]  Domain                      : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.CsDomain
Add-Content -Path $CurrentPath"\"$ReportName -Value "Domain              : $ComData.CsDomain"

Write-Host -ForegroundColor $TextColor "[+]  Workgroup                   : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.CsWorkgroup
Add-Content -Path $CurrentPath"\"$ReportName -Value "Workgroup           : $ComData.CsWorkgroup"

Write-Host -ForegroundColor $TextColor "[+]  Primary Owner               : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.CsPrimaryOwnerName
Add-Content -Path $CurrentPath"\"$ReportName -Value "Primary Owner       : $ComData.CsPrimaryOwnerName"

Write-Host " "
Write-Host -ForegroundColor $AppInfoColor "########## Operating System #########"
Write-Host -ForegroundColor $TextColor "[+]  OS Name                     : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsName
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS Name             : $ComData.osname"

Write-Host -ForegroundColor $TextColor "[+]  OS Version                  : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsVersion
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS Version          : $ComData.osVersion"

Write-Host -ForegroundColor $TextColor "[+]  OS Build Number             : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsBuildNumber
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS Build Numbner    : $ComData.osBuildNumber"

Write-Host -ForegroundColor $TextColor "[+]  OS Language                 : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsLanguage
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS Language         : $ComData.osLanguage"

Write-Host -ForegroundColor $TextColor "[+]  OS Time Zone                : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.TimeZone
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS Time Zone        : $ComData.TimeZone"

Write-Host -ForegroundColor $TextColor "[+]  OS Last Boot Time           : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsLastBootUpTime
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS Last Boot Time   : $ComData.osLastBootUpTime"

Write-Host -ForegroundColor $TextColor "[+]  OS Uptime                   : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsUptime
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS Uptime           : $ComData.osUptime"

Write-Host -ForegroundColor $TextColor "[+]  OS System Drive             : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsSystemDrive
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS System Drive     : $ComData.osSystemDrive"

Write-Host -ForegroundColor $TextColor "[+]  OS Directory                : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsWindowsDirectory
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS Directory        : $ComData.osWindowsDirectory"

Write-Host -ForegroundColor $TextColor "[+]  OS System Directory         : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsSystemDirectory
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS System Directory : $ComData.osSystemDirectory"

Write-Host -ForegroundColor $TextColor "[+]  OS Page File(s)             : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsPagingFiles
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS Page File(s)     : $ComData.osPagingFiles"

Write-Host -ForegroundColor $TextColor "[+]  App Data                    : " -NoNewline
Write-Host -ForegroundColor $DataColor $env:APPDATA
Add-Content -Path $CurrentPath"\"$ReportName -Value "App Data            : $env:APPDATA"

$Path = $env:Path
$PathSplit = $Path.Split(";")
Write-Host -ForegroundColor $TextColor "[+]  Path                        : "
foreach ($Pathitem in $PathSplit){
      Write-Host -Foregroundcolor $DataColor "                                  $Pathitem"
      Add-Content -Path $CurrentPath"\"$ReportName -Value "                          $PathItem"
}
Add-Content -Path $CurrentPath"\"$ReportName -Value "Path                     : $env:Path"

Write-Host " "
Write-Host -ForegroundColor $AppInfoColor "########## System Architecture #########"
Write-Host -ForegroundColor $TextColor "[+]  OS Architecture             : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.OsArchitecture
Add-Content -Path $CurrentPath"\"$ReportName -Value "OS Architecture     : $ComData.osarchitecture"

Write-Host -ForegroundColor $TextColor "[+]  System Type                 : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.CsSystemType
Add-Content -Path $CurrentPath"\"$ReportName -Value "System Type         : $ComData.CsSystemType"

Write-Host -ForegroundColor $TextColor "[+]  Processors                  : " -NoNewline
Write-Host -ForegroundColor $DataColor $ComData.CsProcessors
Add-Content -Path $CurrentPath"\"$ReportName -Value "Processors          : $ComData.CsProcessors"

Write-Host -ForegroundColor $TextColor "[+]  Number of Cores             : " -NoNewline
Write-Host -ForegroundColor $DataColor $env:NUMBER_OF_PROCESSORS
Add-Content -Path $CurrentPath"\"$ReportName -Value "Number Of Cores     : $env:NUMBER_OF_PROCESSORS"

Write-Host -ForegroundColor $TextColor "[+]  Total Memory                : " -NoNewline
$TotMem = $ComData.OsTotalVisibleMemorySize / 1000000 
Write-Host -ForegroundColor $DataColor $TotMem "GB"
Add-Content -Path $CurrentPath"\"$ReportName -Value "Total Memory        : $TotMem GB"

Write-Host -ForegroundColor $TextColor "[+]  Free Memory                 : " -NoNewline
$FreeMem = $ComData.OsFreePhysicalMemory / 1000000 
Write-Host -ForegroundColor $DataColor $FreeMem "GB"
Add-Content -Path $CurrentPath"\"$ReportName -Value "Free Memory         : $FreeMem GB"

Write-Host ""

#==================================
#   Get Network Info
#==================================
Write-Host -ForegroundColor $AppInfoColor "##############################"
Write-Host -ForegroundColor $AppInfoColor "Gathering Network Information"
Write-Host -ForegroundColor $AppInfoColor "##############################"
Add-Content -Path $CurrentPath"\"$ReportName -Value "`r##############################"
Add-Content -Path $CurrentPath"\"$ReportName -Value " Gathering Network Information"
Add-Content -Path $CurrentPath"\"$ReportName -Value "##############################"

#### Network card info here ####




$NetworkStates = @("Established","Listen","Closed","CloseWait","Closing","TimeWait","Bound","DeleteTCB","FinWait1","FinWait2","LastAck","SynReceived","SynSent")
$NetworkStatesLen = $NetworkStates.Length
for ($x = 0; $x -lt $NetworkStatesLen; $x++){
      $NetworkState = $NetworkStates[$x]
      Write-Host " "
      Write-Host -ForegroundColor $AppInfoColor "[+]  Collecting $NetworkState Network Connections"
      Start-Sleep -s 2
      try {
            $Connections = Get-NetTCPConnection -State $NetworkState |Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State,@{name='ProcessName';expression={(Get-Process -Id $_.OwningProcess). Path}} | Format-Table
            $ConnectionsStringTemp = $Connections | Out-String
            $ConnectionsString = $ConnectionsStringTemp.Trim()
            Write-Host -ForegroundColor $DataColor $ConnectionsString
            Add-Content -Path $CurrentPath"\"$ReportName -Value "`r`n [+] $NetworkState Network Connections"
            Add-Content -Path $CurrentPath"\"$ReportName -Value "`r`n $ConnectionsString"
      }
      catch {
            Write-Host -ForegroundColor $DataColor "     No" $NetworkState "Connections Found."
            Add-Content -Path $CurrentPath"\"$ReportName -Value "`r`n [+] $NetworkState Network Connections"
            Add-Content -Path $CurrentPath"\"$ReportName -Value "`r`n     No $NetworkState Connections Found."
      }
}