/*
    YARA Rules for NSO Group Pegasus Spyware
    81 Known Process Names from Amnesty International STIX2 Data
    
    IMPORTANT: These rules are designed for PROCESS NAME matching only.
    Do NOT use for binary content scanning — too many false positives.
    
    Usage:
      yara pegasus_processes.yar <process_list_file>
    
    Author: Pegasus-Sweep IOC Database
    Date: 2026-10-25
    Version: 3.0.1
*/

rule Pegasus_Process_Names_1
{
    meta:
        description = "Detects Pegasus process names (batch 1)"
        author = "Amnesty International / Pegasus-Sweep"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $p1 = "ABSCarryLog" ascii wide nocase
        $p2 = "CommsCenterRootHelper" ascii wide nocase
        $p3 = "Diagnostic-2543" ascii wide nocase
        $p4 = "Diagnosticd" ascii wide nocase
        $p5 = "Diagnostics-2543" ascii wide nocase
        $p6 = "GoldenGate" ascii wide nocase
        $p7 = "JarvisPluginMgr" ascii wide nocase
        $p8 = "MobileSMSd" ascii wide nocase
        $p9 = "PDPDialogs" ascii wide nocase
        $p10 = "ReminderIntentsUIExtension" ascii wide nocase
    
    condition:
        any of them
}

rule Pegasus_Process_Names_2
{
    meta:
        description = "Detects Pegasus process names (batch 2)"
        author = "Amnesty International / Pegasus-Sweep"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $p11 = "accountpfd" ascii wide nocase
        $p12 = "actmanaged" ascii wide nocase
        $p13 = "aggregatenotd" ascii wide nocase
        $p14 = "appccntd" ascii wide nocase
        $p15 = "bfrgbd" ascii wide nocase
        $p16 = "bh" ascii wide nocase
        $p17 = "bluetoothfs" ascii wide nocase
        $p18 = "boardframed" ascii wide nocase
        $p19 = "brfstagingd" ascii wide nocase
        $p20 = "brstaged" ascii wide nocase
    
    condition:
        any of them
}

rule Pegasus_Process_Names_3
{
    meta:
        description = "Detects Pegasus process names (batch 3)"
        author = "Amnesty International / Pegasus-Sweep"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $p21 = "bundpwrd" ascii wide nocase
        $p22 = "cfprefssd" ascii wide nocase
        $p23 = "ckeblld" ascii wide nocase
        $p24 = "ckkeyrollfd" ascii wide nocase
        $p25 = "comnetd" ascii wide nocase
        $p26 = "comsercvd" ascii wide nocase
        $p27 = "confinstalld" ascii wide nocase
        $p28 = "contextstoremgrd" ascii wide nocase
        $p29 = "corecomnetd" ascii wide nocase
        $p30 = "ctrlfs" ascii wide nocase
    
    condition:
        any of them
}

rule Pegasus_Process_Names_4
{
    meta:
        description = "Detects Pegasus process names (batch 4)"
        author = "Amnesty International / Pegasus-Sweep"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $p31 = "dhcp4d" ascii wide nocase
        $p32 = "eventfssd" ascii wide nocase
        $p33 = "eventsfssd" ascii wide nocase
        $p34 = "eventstorpd" ascii wide nocase
        $p35 = "faskeepd" ascii wide nocase
        $p36 = "fdlibframed" ascii wide nocase
        $p37 = "fmld" ascii wide nocase
        $p38 = "fnotifyd" ascii wide nocase
        $p39 = "frtipd" ascii wide nocase
        $p40 = "fservernetd" ascii wide nocase
    
    condition:
        any of them
}

rule Pegasus_Process_Names_5
{
    meta:
        description = "Detects Pegasus process names (batch 5)"
        author = "Amnesty International / Pegasus-Sweep"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $p41 = "gatekeeperd" ascii wide nocase
        $p42 = "gssdp" ascii wide nocase
        $p43 = "jlmvskrd" ascii wide nocase
        $p44 = "keybrd" ascii wide nocase
        $p45 = "launchafd" ascii wide nocase
        $p46 = "launchrexd" ascii wide nocase
        $p47 = "libbmanaged" ascii wide nocase
        $p48 = "libtouchregd" ascii wide nocase
        $p49 = "llmdwatchd" ascii wide nocase
        $p50 = "lobbrogd" ascii wide nocase
    
    condition:
        any of them
}

rule Pegasus_Process_Names_6
{
    meta:
        description = "Detects Pegasus process names (batch 6)"
        author = "Amnesty International / Pegasus-Sweep"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $p51 = "locserviced" ascii wide nocase
        $p52 = "logseld" ascii wide nocase
        $p53 = "misbrigd" ascii wide nocase
        $p54 = "mobileargd" ascii wide nocase
        $p55 = "mptbd" ascii wide nocase
        $p56 = "msgacntd" ascii wide nocase
        $p57 = "natgd" ascii wide nocase
        $p58 = "neagentd" ascii wide nocase
        $p59 = "nehelprd" ascii wide nocase
        $p60 = "netservcomd" ascii wide nocase
    
    condition:
        any of them
}

rule Pegasus_Process_Names_7
{
    meta:
        description = "Detects Pegasus process names (batch 7)"
        author = "Amnesty International / Pegasus-Sweep"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $p61 = "otpgrefd" ascii wide nocase
        $p62 = "passsd" ascii wide nocase
        $p63 = "payload" ascii wide nocase
        $p64 = "pcsd" ascii wide nocase
        $p65 = "pstid" ascii wide nocase
        $p66 = "rlaccountd" ascii wide nocase
        $p67 = "roleaboutd" ascii wide nocase
        $p68 = "roleaccountd" ascii wide nocase
        $p69 = "rolexd" ascii wide nocase
        $p70 = "seraccountd" ascii wide nocase
    
    condition:
        any of them
}

rule Pegasus_Process_Names_8
{
    meta:
        description = "Detects Pegasus process names (batch 8)"
        author = "Amnesty International / Pegasus-Sweep"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $p71 = "setframed" ascii wide nocase
        $p72 = "smmsgingd" ascii wide nocase
        $p73 = "stagegrad" ascii wide nocase
        $p74 = "stagingd" ascii wide nocase
        $p75 = "tisppd" ascii wide nocase
        $p76 = "updaterd" ascii wide nocase
        $p77 = "vm_stats" ascii wide nocase
        $p78 = "wifip2ppd" ascii wide nocase
        $p79 = "xpccfd" ascii wide nocase
    
    condition:
        any of them
}

rule NSO_Infection_Vectors
{
    meta:
        description = "Detects NSO Group infection vector names"
        author = "Pegasus-Sweep / Amnesty Security Lab"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
        reference = "https://securitylab.amnesty.org/latest/2026/07/inside-pegasus-the-evolution-of-the-worlds-most-notorious-spyware/"
    
    strings:
        $v1 = "Heaven" ascii wide nocase
        $v2 = "Erised" ascii wide nocase
        $v3 = "Eden" ascii wide nocase
        $v4 = "Hummingbird" ascii wide nocase
        $v5 = "iOS Covert" ascii wide nocase
        $v6 = "Android Covert" ascii wide nocase
    
    condition:
        any of them
}

rule NSO_Product_Names
{
    meta:
        description = "Detects NSO Group product names"
        author = "Pegasus-Sweep"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $n1 = "pegasus" ascii wide nocase
        $n2 = "phantom" ascii wide nocase
        $n3 = "chrysaor" ascii wide nocase
        $n4 = "quadrant" ascii wide nocase
        $n5 = "novalight" ascii wide nocase
        $n6 = "circles" ascii wide nocase
        $n7 = "nso" ascii wide
    
    condition:
        any of them
}

rule Candiru_Products
{
    meta:
        description = "Detects Candiru spyware product names"
        author = "Pegasus-Sweep / Citizen Lab"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $c1 = "devilstongue" ascii wide nocase
        $c2 = "sourgum" ascii wide nocase
        $c3 = "sand cat" ascii wide nocase
        $c4 = "caramel tsunami" ascii wide nocase
        $c5 = "saito" ascii wide nocase
    
    condition:
        any of them
}

rule Intellexa_Products
{
    meta:
        description = "Detects Intellexa/Cytrox spyware product names"
        author = "Pegasus-Sweep / Amnesty Security Lab"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $i1 = "predator" ascii wide nocase
        $i2 = "cytrox" ascii wide nocase
        $i3 = "intellexa" ascii wide nocase
    
    condition:
        any of them
}

rule Paragon_Products
{
    meta:
        description = "Detects Paragon Solutions spyware product names"
        author = "Pegasus-Sweep / Citizen Lab"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "high"
        severity = "critical"
        scope = "process_name"
    
    strings:
        $g1 = "graphite" ascii wide nocase
        $g2 = "paragon" ascii wide nocase
    
    condition:
        any of them
}

rule Spyware_Tools
{
    meta:
        description = "Detects common spyware/injection tools"
        author = "Pegasus-Sweep"
        date = "2026-10-25"
        version = "3.0.1"
        confidence = "medium"
        severity = "high"
        scope = "process_name"
    
    strings:
        $t1 = "mimikatz" ascii wide nocase
        $t2 = "psexec" ascii wide nocase
        $t3 = "cobalt" ascii wide nocase
        $t4 = "beacon" ascii wide nocase
        $t5 = "metasploit" ascii wide nocase
        $t6 = "meterpreter" ascii wide nocase
        $t7 = "frida" ascii wide nocase
        $t8 = "cycript" ascii wide nocase
        $t9 = "substrate" ascii wide nocase
        $t10 = "cynject" ascii wide nocase
    
    condition:
        any of them
}
