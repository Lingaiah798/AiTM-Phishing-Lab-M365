# ============================================================
# audit-mailbox.ps1
# AiTM Phishing Lab - Mailbox Audit Script
# Purpose: READ-ONLY audit of a potentially compromised mailbox
# Safe to run - makes NO changes to the environment
# ============================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$UserEmail
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " AiTM Phishing - Mailbox Audit Script" -ForegroundColor Cyan
Write-Host " Target: $UserEmail" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ---- 1. CAS Mailbox Settings (Protocol Access) ----
Write-Host "[1] Checking CAS Mailbox Settings (Protocol Access)..." -ForegroundColor Yellow
Get-CASMailbox -Identity $UserEmail | 
Select-Object DisplayName, ImapEnabled, PopEnabled, ActiveSyncEnabled, OWAEnabled, MAPIEnabled, EWSEnabled |
Format-List

# ---- 2. OWA Mailbox Policy ----
Write-Host "[2] Checking OWA Mailbox Policy..." -ForegroundColor Yellow
Get-CASMailbox -Identity $UserEmail | Select-Object OwaMailboxPolicy | Format-List

# ---- 3. Inbox Rules (Check for forwarding/deletion rules) ----
Write-Host "[3] Checking Inbox Rules..." -ForegroundColor Yellow
$rules = Get-InboxRule -Mailbox $UserEmail
if ($rules) {
    $rules | Select-Object Name, Enabled, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, MoveToFolder | Format-List
    Write-Host "⚠️  ALERT: $($rules.Count) inbox rule(s) found - review carefully!" -ForegroundColor Red
} else {
    Write-Host "✅ No inbox rules found." -ForegroundColor Green
}

# ---- 4. Recent Sign-In Activity ----
Write-Host "[4] Checking Recent Sign-In Activity (Last 7 Days)..." -ForegroundColor Yellow
Search-UnifiedAuditLog `
    -StartDate (Get-Date).AddDays(-7) `
    -EndDate (Get-Date) `
    -UserIds $UserEmail `
    -Operations "UserLoggedIn","UserLoginFailed" `
    -ResultSize 20 | 
Select-Object CreationDate, Operation, 
    @{N="IPAddress";E={($_.AuditData | ConvertFrom-Json).ClientIP}},
    @{N="UserAgent";E={($_.AuditData | ConvertFrom-Json).ExtendedProperties | Where-Object {$_.Name -eq "UserAgent"} | Select-Object -ExpandProperty Value}} |
Format-Table -AutoSize

# ---- 5. URL Clicks (Check for phishing link clicks) ----
Write-Host "[5] Checking URL Click Events (Last 7 Days)..." -ForegroundColor Yellow
$urlClicks = Search-UnifiedAuditLog `
    -StartDate (Get-Date).AddDays(-7) `
    -EndDate (Get-Date) `
    -UserIds $UserEmail `
    -Operations "UrlClicked" `
    -ResultSize 50

if ($urlClicks) {
    Write-Host "⚠️  ALERT: URL click events found!" -ForegroundColor Red
    $urlClicks | ForEach-Object {
        $data = $_.AuditData | ConvertFrom-Json
        [PSCustomObject]@{
            Time      = $_.CreationDate
            URL       = $data.Url
            Verdict   = $data.UrlVerdict
        }
    } | Format-Table -AutoSize
} else {
    Write-Host "✅ No URL click events found." -ForegroundColor Green
}

# ---- 6. Mail Forwarding Check ----
Write-Host "[6] Checking Mail Forwarding Settings..." -ForegroundColor Yellow
Get-Mailbox -Identity $UserEmail | 
Select-Object ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward |
Format-List

# ---- 7. Recently Created Delegate Access ----
Write-Host "[7] Checking Mailbox Delegates..." -ForegroundColor Yellow
Get-MailboxPermission -Identity $UserEmail | 
Where-Object {$_.User -notlike "NT AUTHORITY*" -and $_.IsInherited -eq $false} |
Format-Table User, AccessRights, IsInherited -AutoSize

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Audit Complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
