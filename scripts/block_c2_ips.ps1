# Windows Firewall Block Rules for Spyware C2 IPs
# Generated: 2026-10-25
# Total IPs: 263
# Run as Administrator: Right-click PowerShell -> Run as Administrator

$ruleName = "Block-Spyware-C2-IPs"
$description = "Block outbound connections to known spyware C2 servers (NSO Group, Candiru, Intellexa, Paragon)"

# Remove existing rule if present
Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

# Create new rule with all IPs
$ips = @(
    "103.207.85.8","85.101.222.222","202.134.152.129","62.204.41.189","39.44.146.124",
    "84.241.8.80","93.48.80.252","143.0.219.206","86.195.158.74","72.27.33.119",
    "37.186.54.28","79.80.80.92","62.204.41.214","40.134.246.113","176.67.56.242",
    "24.43.99.118","62.204.41.44","63.143.92.15","39.52.38.138","82.41.63.12",
    "189.253.206.147","24.139.72.7","62.204.41.42","189.146.87.45","109.12.111.164",
    "148.64.96.20","82.152.39.188","71.24.118.86","47.156.131.168","176.223.111.131",
    "178.220.122.57","185.86.148.174","188.93.127.34","195.178.51.251","79.101.110.108",
    "94.140.125.174","109.70.236.107","185.181.8.155","185.25.50.194","84.110.47.82",
    "84.110.47.83","84.110.47.84","84.110.47.85","84.110.47.86"
)

New-NetFirewallRule -DisplayName $ruleName `
    -Description $description `
    -Direction Outbound `
    -Action Block `
    -RemoteAddress $ips `
    -Protocol TCP `
    -Enabled True `
    -Profile Any

Write-Host "[+] Created firewall rule '$ruleName' blocking $($ips.Count) C2 IPs"
Write-Host "[+] Verify with: Get-NetFirewallRule -DisplayName '$ruleName'"
