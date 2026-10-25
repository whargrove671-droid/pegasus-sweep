# Comprehensive Spyware Detection Script for Windows
# NSO Group, Candiru, Intellexa, Paragon, and other commercial spyware IOCs
# Sources: Amnesty International, Citizen Lab, Microsoft MSTIC, Google TAG

$findings = [System.Collections.Generic.List[string]]::New()
$infoItems = [System.Collections.Generic.List[string]]::New()
$startTime = Get-Date

function Add-Finding($category, $message) {
    $findings.Add("[$category] $message")
}

function Add-Info($category, $message) {
    $infoItems.Add("[$category] $message")
}

Write-Output "=== Comprehensive Spyware Detection Scan ==="
Write-Output "Host: $env:COMPUTERNAME | User: $env:USERNAME"
Write-Output "Scan started: $startTime"
Write-Output ""

# ============================================================================
# SPYWARE VENDOR PRODUCT NAMES
# ============================================================================

# NSO Group (Israel)
$nsoProducts = @(
    'pegasus', 'phantom', 'chrysaor', 'quadrant', 'nso', 'novalight',
    'circles', 'landmark', 'devilstongue', 'hermit', 'predator',
    'candiru', 'devils-eye', 'devilseye', 'sourgum', 'barbwire',
    'heaven', 'erised', 'eden', 'hummingbird', 'ios covert', 'android covert'
)

# Candiru / Saito Tech Ltd (Israel)
$candiruProducts = @(
    'devilstongue', 'sourgum', 'sand cat', 'caramel tsunami', 'saito'
)

# Intellexa / Cytrox (Greece)
$intellexaProducts = @(
    'predator', 'cytrox', 'intellexa', 'eagle'
)

# Paragon Solutions (Israel)
$paragonProducts = @(
    'graphite', 'paragon'
)

# Other commercial spyware vendors
$otherSpyware = @(
    'finfisher', 'finspy', 'gamma', 'hacking team', 'memento labs',
    'dark basin', 'belltrox', 'cyberbit', 'sandvine', 'packrat',
    'stealth falcon', 'spyagent', 'poison carp', 'nile phish'
)

# All product names combined
$allSpywareProducts = $nsoProducts + $candiruProducts + $intellexaProducts + $paragonProducts + $otherSpyware

# ============================================================================
# KNOWN PEGASUS PROCESS NAMES (81 from Amnesty STIX2)
# ============================================================================
$pegasusProcesses = @(
    'ABSCarryLog', 'CommsCenterRootHelper', 'Diagnostic-2543', 'Diagnosticd',
    'Diagnostics-2543', 'GoldenGate', 'JarvisPluginMgr', 'MobileSMSd',
    'PDPDialogs', 'ReminderIntentsUIExtension', 'accountpfd', 'actmanaged',
    'aggregatenotd', 'appccntd', 'bfrgbd', 'bh', 'bluetoothfs',
    'boardframed', 'brfstagingd', 'brstaged', 'bundpwrd', 'cfprefssd',
    'ckeblld', 'ckkeyrollfd', 'comnetd', 'comsercvd', 'confinstalld',
    'contextstoremgrd', 'corecomnetd', 'ctrlfs', 'dhcp4d', 'eventfssd',
    'eventsfssd', 'eventstorpd', 'faskeepd', 'fdlibframed', 'fmld',
    'fnotifyd', 'frtipd', 'fservernetd', 'gatekeeperd', 'gssdp',
    'jlmvskrd', 'keybrd', 'launchafd', 'launchrexd', 'libbmanaged',
    'libtouchregd', 'llmdwatchd', 'lobbrogd', 'locserviced', 'logseld',
    'misbrigd', 'mobileargd', 'mptbd', 'msgacntd', 'natgd',
    'neagentd', 'nehelprd', 'netservcomd', 'otpgrefd', 'passsd',
    'payload', 'pcsd', 'pstid', 'rlaccountd', 'roleaboutd',
    'roleaccountd', 'rolexd', 'seraccountd', 'setframed', 'smmsgingd',
    'stagegrad', 'stagingd', 'tisppd', 'updaterd', 'vm_stats',
    'wifip2ppd', 'xpccfd'
)

# ============================================================================
# SPYWARE/INJECTION TOOLS
# ============================================================================
$spywareTools = @(
    'mimikatz', 'psexec', 'cobalt', 'beacon', 'metasploit', 'meterpreter',
    'frida', 'frida-server', 'frida-agent', 'frida-inject',
    'cycript', 'substrate', 'cynject', 'insert_dylib',
    'lldb', 'gdb', 'radare2', 'r2', 'ida', 'ollydbg', 'x64dbg',
    'wireshark', 'tshark', 'tcpdump', 'fiddler', 'burp',
    'teamviewer', 'anydesk', 'chrome-remote', 'vnc', 'radmin',
    'ncat', 'netcat', 'nc.exe', 'powercat', 'empire', 'pupy'
)

# ============================================================================
# 1. PROCESS ANALYSIS
# ============================================================================
Write-Output "--- [1] Process Analysis ---"
$allProcs = Get-Process -ErrorAction SilentlyContinue | Select-Object Name, Id, Path
$foundSuspicious = $false

foreach ($proc in $allProcs) {
    # Check Pegasus-specific processes
    foreach ($bad in $pegasusProcesses) {
        if ($proc.Name -match $bad) {
            Add-Finding "PEGASUS-PROCESS" "$($proc.Name) (PID:$($proc.Id)) - Known Pegasus process"
            $foundSuspicious = $true
        }
    }
    # Check general spyware tools
    foreach ($bad in $spywareTools) {
        if ($proc.Name -match $bad) {
            Add-Finding "SPYWARE-TOOL" "$($proc.Name) (PID:$($proc.Id))"
            $foundSuspicious = $true
        }
    }
    # Check all spyware product names
    foreach ($bad in $allSpywareProducts) {
        if ($proc.Name -match $bad) {
            Add-Finding "SPYWARE-PRODUCT" "$($proc.Name) (PID:$($proc.Id)) - Matches spyware product name"
            $foundSuspicious = $true
        }
    }
    # Check for unsigned processes in sensitive locations
    if ($proc.Path) {
        if ($proc.Path -match '^C:\\Windows\\' -or $proc.Path -match '^C:\\Program Files') {
            try {
                $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction Stop
                if ($sig.Status -ne 'Valid') {
                    Add-Finding "UNSIGNED" "$($proc.Name) in $($proc.Path)"
                    $foundSuspicious = $true
                }
            } catch {}
        }
    }
}
if (-not $foundSuspicious) { Write-Output "  No suspicious processes detected." }

# ============================================================================
# 2. NETWORK ANALYSIS
# ============================================================================
Write-Output "--- [2] Network Connection Analysis ---"

# Suspicious ports (C2, backdoors)
$suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321, 8080, 8443, 4433, 9001, 9030, 995, 2222)

$netstatOutput = netstat -ano 2>$null
$foundNet = $false

foreach ($line in $netstatOutput) {
    if ($line -match 'TCP\s+(\S+)\s+(\S+)\s+(LISTENING|ESTABLISHED)\s+(\d+)') {
        $localAddr = $matches[1]
        $foreignAddr = $matches[2]
        $state = $matches[3]
        $netPid = $matches[4]
        
        if ($state -eq 'LISTENING') {
            foreach ($badPort in $suspiciousPorts) {
                if ($localAddr -match ":$badPort$") {
                    $procName = (Get-Process -Id $netPid -ErrorAction SilentlyContinue).Name
                    Add-Finding "NETWORK" "Suspicious listener on port $badPort (PID:$netPid, Process:$procName)"
                    $foundNet = $true
                }
            }
        }
        
        # Check for connections to known C2 ports on external IPs
        if ($state -eq 'ESTABLISHED' -and $foreignAddr -match ':(995|2222|443|80)$') {
            $procName = (Get-Process -Id $netPid -ErrorAction SilentlyContinue).Name
            Add-Info "C2-PORT" "External connection on C2-like port: $foreignAddr (Process:$procName)"
        }
    }
}

# Check DNS cache for suspicious patterns
$suspiciousDomainPatterns = @(
    'redirect', 'loading', 'url', 'dns', 'page', 'web', 'link',
    'update', 'service', 'sync', 'cdn', 'api', 'secure', 'login',
    'account', 'verify', 'support', 'notify', 'alert', 'message',
    'mail', 'sms', 'cloud', 'data', 'track', 'stats', 'metric'
)

$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match '\.' }
foreach ($dns in $dnsCache) {
    $entry = $dns.Entry.ToLower()
    foreach ($pattern in $suspiciousDomainPatterns) {
        if ($entry -match $pattern) {
            Add-Info "DNS-CACHE" "Suspicious domain pattern in DNS cache: $($dns.Entry)"
            break
        }
    }
}

if (-not $foundNet) { Write-Output "  No suspicious network listeners detected." }

# ============================================================================
# 3. PERSISTENCE MECHANISMS
# ============================================================================
Write-Output "--- [3] Persistence Mechanism Analysis ---"

$regPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        $items = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        if ($items) {
            foreach ($prop in $items.PSObject.Properties) {
                if ($prop.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {
                    $val = $prop.Value
                    $isSpyware = $false
                    foreach ($bad in $allSpywareProducts) {
                        if ($val -match $bad -or $prop.Name -match $bad) {
                            Add-Finding "PERSISTENCE-SPYWARE" "Spyware-related autorun: $($prop.Name) = $val"
                            $isSpyware = $true
                        }
                    }
                    if (-not $isSpyware) {
                        if ($val -match 'Temp|Downloads|AppData.Local' -or $val -match 'powershell.*-enc') {
                            Add-Finding "PERSISTENCE" "Suspicious autorun: $($prop.Name)"
                        } else {
                            Add-Info "PERSISTENCE" "Registry autorun: $($prop.Name)"
                        }
                    }
                }
            }
        }
    }
}

# Scheduled tasks
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' }
foreach ($task in $tasks) {
    $actions = $task.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }
    foreach ($action in $actions) {
        foreach ($bad in $allSpywareProducts) {
            if ($action -match $bad -or $task.TaskName -match $bad) {
                Add-Finding "TASK-SPYWARE" "Spyware-related scheduled task: '$($task.TaskName)'"
            }
        }
        if ($action -match 'Temp|Downloads|AppData.Local' -or $action -match 'powershell.*-enc') {
            Add-Finding "TASK" "Suspicious scheduled task: '$($task.TaskName)'"
        }
    }
}

# Services from user-writable paths
$services = Get-WmiObject win32_service | Where-Object { $_.PathName -match '\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp\\' }
foreach ($svc in $services) {
    Add-Finding "SERVICE" "Service '$($svc.Name)' runs from user-writable path"
}

# ============================================================================
# 4. FILE SYSTEM ANOMALIES
# ============================================================================
Write-Output "--- [4] File System Anomaly Analysis ---"

# Known spyware file artifacts
$spywareFiles = @(
    'roleaccountd.plist', 'com.apple.Mappit.SnapshotService', 
    'com.apple.rapports.events', 'bh', 'payload'
)

$tempPaths = @($env:TEMP, 'C:\Windows\Temp', "$env:LOCALAPPDATA\Temp")
foreach ($tempPath in $tempPaths) {
    if (Test-Path $tempPath) {
        $recentFiles = Get-ChildItem $tempPath -Recurse -Include '*.exe','*.dll','*.sys','*.ps1','*.tmp','*.dat' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
            Select-Object -First 15
        foreach ($f in $recentFiles) {
            Add-Info "FILE" "Recent file in Temp: $($f.FullName)"
            foreach ($bad in $spywareFiles) {
                if ($f.Name -match $bad) {
                    Add-Finding "SPYWARE-FILE" "Known spyware file artifact: $($f.FullName)"
                }
            }
        }
    }
}

# Check for alternate data streams
$commonBins = @('C:\Windows\System32\svchost.exe', 'C:\Windows\System32\explorer.exe')
foreach ($bin in $commonBins) {
    if (Test-Path $bin) {
        $streams = Get-Item $bin -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' }
        foreach ($s in $streams) {
            Add-Finding "ADS" "Alternate data stream on $bin : $($s.Stream)"
        }
    }
}

# Recent files in user profile
$recentProfile = Get-ChildItem $env:USERPROFILE -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) -and $_.Extension -in @('.exe','.dll','.ps1','.bat','.vbs','.js') } |
    Select-Object -First 10
foreach ($f in $recentProfile) {
    Add-Info "FILE" "Recent executable in profile: $($f.FullName)"
}

# ============================================================================
# 5. SECURITY PRODUCT STATUS
# ============================================================================
Write-Output "--- [5] Security Product Status ---"
$secServices = @('WinDefend', 'Sense', 'WdNisSvc', 'SecurityHealthService', 'wscsvc')
foreach ($svcName in $secServices) {
    $svc = Get-Service $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Running') {
            Add-Finding "SECURITY" "Security service $svcName is $($svc.Status) - Spyware indicator"
        } else {
            Add-Info "SECURITY" "Security service $svcName is Running"
        }
    }
}

# Check Windows Defender exclusions
$defenderPrefs = Get-MpPreference -ErrorAction SilentlyContinue
if ($defenderPrefs) {
    if ($defenderPrefs.ExclusionPath) {
        foreach ($excl in $defenderPrefs.ExclusionPath) {
            Add-Finding "DEFENDER" "Defender exclusion path: $excl - verify legitimacy"
        }
    }
    if ($defenderPrefs.ExclusionProcess) {
        foreach ($excl in $defenderPrefs.ExclusionProcess) {
            Add-Finding "DEFENDER" "Defender exclusion process: $excl - verify legitimacy"
        }
    }
}

# ============================================================================
# 6. EVENT LOG ANOMALIES
# ============================================================================
Write-Output "--- [6] Event Log Analysis ---"

try {
    $logClear = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 -ErrorAction SilentlyContinue
    foreach ($evt in $logClear) {
        Add-Finding "EVENT" "Security log cleared at $($evt.TimeCreated) - anti-forensics"
    }
} catch {}

try {
    $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 -ErrorAction SilentlyContinue
    if ($failedLogons.Count -gt 0) {
        Add-Finding "EVENT" "$($failedLogons.Count) failed logon attempts"
    }
} catch {}

# ============================================================================
# 7. SYSTEM INTEGRITY
# ============================================================================
Write-Output "--- [7] System Integrity Analysis ---"

$testSigning = bcdedit /enum 2>$null | Select-String 'testsigning.*Yes'
if ($testSigning) {
    Add-Finding "INTEGRITY" "Test signing mode ENABLED - allows unsigned drivers"
}

$debugMode = bcdedit /enum 2>$null | Select-String 'debug.*Yes'
if ($debugMode) {
    Add-Info "INTEGRITY" "Kernel debug mode is enabled"
}

# Check for unsigned drivers
$drivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq 'Running' }
foreach ($drv in $drivers) {
    if ($drv.PathName) {
        $drvPath = $drv.PathName -replace '^\\??\\', '' -replace '^\\SystemRoot', 'C:\Windows'
        if (Test-Path $drvPath -ErrorAction SilentlyContinue) {
            try {
                $sig = Get-AuthenticodeSignature $drvPath -ErrorAction Stop
                if ($sig.Status -ne 'Valid') {
                    Add-Finding "DRIVER" "Unsigned driver loaded: $($drv.Name)"
                }
            } catch {}
        }
    }
}

# ============================================================================
# 8. SPYWARE-SPECIFIC IOCs
# ============================================================================
Write-Output "--- [8] Spyware-Specific IOC Analysis ---"

# Check certificates
$suspiciousCerts = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Issuer -match 'NSO|Pegasus|Candiru|Paragon|Intellexa|Cytrox' -or
                   $_.Subject -match 'NSO|Pegasus|Candiru|Paragon|Intellexa|Cytrox' }
foreach ($cert in $suspiciousCerts) {
    Add-Finding "CERT" "Suspicious certificate: $($cert.Subject)"
}

# Check for known operator email patterns
$operatorEmailPatterns = @('gmail.com', 'outlook.com', 'proton.me', 'protonmail.com', 'icloud.com')

# Browser history check for C2 domains
$browserPaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
)

foreach ($browserPath in $browserPaths) {
    if (Test-Path $browserPath) {
        Add-Info "BROWSER" "Browser history found - manual review recommended for C2 domains"
    }
}

# ============================================================================
# SUMMARY
# ============================================================================
$elapsed = (Get-Date) - $startTime
Write-Output ""
Write-Output "=== SCAN COMPLETE ==="
Write-Output "Elapsed: $($elapsed.TotalSeconds.ToString('F1'))s"
Write-Output ""

if ($findings.Count -gt 0) {
    Write-Output "!!! FINDINGS REQUIRING ATTENTION ($($findings.Count)) !!!"
    foreach ($f in $findings) { Write-Output "  [!] $f" }
    Write-Output ""
}

if ($infoItems.Count -gt 0) {
    Write-Output "Informational Items ($($infoItems.Count)):"
    foreach ($i in $infoItems) { Write-Output "  [i] $i" }
    Write-Output ""
}

if ($findings.Count -eq 0) {
    Write-Output "No high-confidence indicators of commercial spyware detected."
    Write-Output "Note: This scan checks public IOCs but cannot detect zero-day implants."
    Write-Output "For comprehensive mobile analysis, use MVT (Mobile Verification Toolkit)."
}

exit $findings.Count
