# Current User or specific user ?
param (
  [Parameter(Mandatory=$false)][string]$User=$null
)
function CheckSecurityLevel {

  # Self-elevate the script if required
  if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {  
      $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " 
      Write-Host "Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine"
      Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
      Exit
    }
  }


}
function Reload-InternetOptions
{
  $signature = @'
[DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int
dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
  $interopHelper = Add-Type -MemberDefinition $signature -Name MyInteropHelper -PassThru

  $INTERNET_OPTION_SETTINGS_CHANGED = 39
  $INTERNET_OPTION_REFRESH = 37

  $result1 = $interopHelper::InternetSetOption(0, $INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
  $result2 = $interopHelper::InternetSetOption(0, $INTERNET_OPTION_REFRESH, 0, 0)

  $result1 -and $result2
}
function Write-Color([String[]]$Text, [ConsoleColor[]]$Color) {
  for ($i = 0; $i -lt $Text.Length; $i++) {
      Write-Host $Text[$i] -Foreground $Color[$i] -NoNewLine
  }
  Write-Host
}
function LoadParams{
  # Write-Host "Load $PSScriptRoot\AutoSwitchProxy.yml" -ForegroundColor DarkCyan
  Write-Color -Text "Load            --> ", $PSScriptRoot\AutoSwitchProxy.yml -color Green,Yellow

  $script:Params    = ConvertFrom-Yaml -Ordered -AllDocuments -Yaml (Get-Content -Path "$PSScriptRoot\AutoSwitchProxy.yml" -Raw)
    
  $script:Profiles  = $Params.Profiles
  $script:SplitChar = $Params.SplitChar

}
function CheckCurrentCnx {

  # view all NetworkList profiles
  # Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\"
  # Get-NetAdapter | % { Process { If (( $_.Status -eq "up" ) -and ($_.InterfaceDescription -notlike "Hyper-V*") ){ $_ } }}
  # Get-DnsClient -InterfaceAlias Ethernet

  $InterfaceAlias=$(Get-NetAdapter | % { Process { If (( $_.Status -eq "up" ) -and ($_.InterfaceDescription -notlike "Hyper-V*") ){ $_ } }}).InterfaceAlias
  $DNSSuffix=$(Get-DnsClient -InterfaceAlias $InterfaceAlias).ConnectionSpecificSuffix

  foreach ( $tmp in $Params.Profiles.Split($Params.SplitChar) )
  {
    $Profile          = $tmp.replace(' ' , '')
    $SSID = $null

    # Get all SSID ...
    foreach ($SSID_tmp in $Params[$Profile]."SSIDLNetworkList".Split($Params.SplitChar) ){
      if ( ! $SSID ) {$SSID = $SSID_tmp.replace(' ' , '') } else { $SSID = $SSID +"|"+ $SSID_tmp.replace(' ' , '') }
    }

    Write-Host " "
    Write-Color -Text "`$Profile        --> ",  $Profile, " DNSSuffix -->", $Params[$Profile]."DNSSuffix",  " SSIDLNetworkList -->", $SSID  -color Green,Yellow,Green,Yellow,Green,Yellow

    # Check if DNSSuffix == with Profile's DNSSuffix
    if ( $DNSSuffix -eq $Params[$Profile]."DNSSuffix" ){
      Write-Color -Text "DNSSUffix match --> ",  $Params[$Profile]."DNSSuffix" -color Green,Yellow
      
      # CheckProxy Proxy values
      CheckProxy $Params[$Profile]

    }else{

      # Check last Wireless event
      if ( Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-WLAN-AutoConfig/Operational'; id=8001} -MaxEvents 1 |
        Where-Object -Property Message -Match $SSID | Format-Table TimeCreated,Message -wrap ) { 
          CheckProxy $Params[$Profile]
        }   
    }
  }
  
  # No match works apply Default
  Write-Host " "
  Write-Color -Text "No match works for : ", $User, " Lan : ", $DNSSuffix, " ...Apply default configuration ..."   -color Red,Yellow,Red,Yellow,DarkRed
  # Write-Host "$User : no match works, apply Default configuration" -ForegroundColor Red
  UpdateProxy $Params."Default"
}
function CheckProxy {
  param (
    $ProfilePath=$args[0]
    )
    
  Write-Color -Text "CheckProxy      --> ",  $($ProfilePath."ProxyList".Keys ) -color Green,Yellow

  # Get Proxy config
  foreach ($Prxy in $ProfilePath."ProxyList".Keys){
    Write-Color -Text "`$Prxy:          --> ", $Prxy -color Green,Yellow

    # Get Users in list...if not empty or $null
    if ( $($ProfilePath.'ProxyList'[$Prxy]."UsersList") -and ( $($($ProfilePath.'ProxyList'[$Prxy]."UsersList").replace(" ", "")).Length -gt 0 )){
      
      # Many ou only one user(s)
      if ( $($ProfilePath.'ProxyList'[$Prxy]."UsersList").contains($Params.SplitChar) ){
        $UsersList =  $($ProfilePath.'ProxyList'[$Prxy]."UsersList").Split($Params.SplitChar)
      }else{
        $UsersList =  $($ProfilePath.'ProxyList'[$Prxy]."UsersList")
      }
      
      foreach ($User_ in $UsersList){
        $User_ = $($User_).replace(" ","")
        Write-Color -Text "`$User_          -->", $User_,"<--" -color Green,Yellow, Green

        # Check if user is contains in Profile's users list
        if ( $User_ -eq $User) {
          Write-Color -Text "User match      --> ", $User ," in users List --> ", $ProfilePath.'ProxyList'[$Prxy]."UsersList" -color Green,Yellow, Green,Yellow
          
          # UpdateProxy Proxy values
          UpdateProxy $ProfilePath.'ProxyList'[$Prxy] 
          
          # All done for this user exit...
          exit 00
          } 
      }
    }
  }

  # Match for DNSSuffix or SSIDLNetworkList but no match for the user...Apply Default for this proxy & user
  Write-Host " "
  Write-Color -Text "No user match for : ", $User, " Lan : ", $DNSSuffix, " ...Apply default configuration with Profile : ", $Profile   -color Red,Yellow,Green,Yellow,Green, Yellow

  # UpdateProxy Proxy values
  UpdateProxy $ProfilePath.'ProxyList'["DefaultUser"]

  # All done for user exit...
  exit 00

}
function UpdateProxy {
  param (
    $ProfilePath=$args[0]
  )
  
  $RegPath = $($Params."UserProxySettings").replace('$UserSid.SID',$UserSid.SID)
  Write-Color -Text "UserProxySettings-> ", $RegPath -color Green,Yellow

  if ($ProfilePath."PrxyEnable"){$ProxyStatus=1}else{$ProxyStatus=0}

  # Update Proxy Configuration
  Write-Color -Text "PrxyEnable      --> ", $ProfilePath."PrxyEnable", " --> ", $ProfilePath."PrxyServer" -color Green,Yellow,Green,Yellow
  RegWrite $RegPath "ProxyEnable" $Params."ProxyEnable" $ProxyStatus
  
  Write-Host $RegPath, "ProxyServer", $Params."ProxyServer", $ProfilePath."PrxyServer" -ForegroundColor Yellow
  RegWrite $RegPath "ProxyServer" $Params."ProxyServer" $ProfilePath."PrxyServer"

  $RegPath = $($Params."DisableChangeProxy").replace('$UserSid.SID',$UserSid.SID)
  Write-Color -Text "DisableChangeProxy> ", $RegPath -color Green,Yellow

  # Update Secure Proxy Change Configuration
  Write-Host $RegPath "Proxy" $Params."ScecureProxy" $ProxyStatus -ForegroundColor Yellow
  if ($($ProfilePath."PrxySecure") ){
    RegWrite $RegPath "Proxy" $Params."ScecureProxy" 1
  }else{
    Remove-ItemProperty -Path Registry::$RegPath -Name "Proxy" -ea SilentlyContinue
  }    
}
function RegWrite ($RegPath, $RegName, $RegType, $RegValue) {

  # Write-Host " "
  Write-Color -Text "RegWrite        --> ", "New-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -PropertyType $RegType " -color Green,Yellow
  New-ItemProperty -Path Registry::$RegPath -Name $RegName -Value $RegValue -PropertyType $RegType -Force | select * -exclude PS* | Format-List
}

Clear-Host

# if $User is $null, get current user
if(!($User)){
  $User = $env:USERNAME
}

#Get UserID
$UserSid=(Get-CimInstance -ClassName  win32_useraccount -Filter "LocalAccount = 'True'" | Where-Object {$_.Name -eq $User} | Select-Object name,SID)
if (! $UserSid){
  Write-Host "User : $User not found !" -BackgroundColor DarkRed -ForegroundColor Yellow 
  exit
}

CheckSecurityLevel
LoadParams

Write-Color -Text "User            --> ", $User, " --> ", $UserSid -color Green,Yellow, Green,Yellow

CheckCurrentCnx
Reload-InternetOptions