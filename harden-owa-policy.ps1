# ============================================================
# harden-owa-policy.ps1
# AiTM Phishing Lab - OWA Mailbox Policy Hardening
# ⚠️  WARNING: This script MAKES CHANGES to your environment
# Run audit-mailbox.ps1 first and back up current settings
# ============================================================

# ---- Backup current settings first ----
Write-Host "Backing up current OWA policy settings..." -ForegroundColor Yellow
Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default | 
Format-List | Out-File "OwaPolicy_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Write-Host "✅ Backup saved." -ForegroundColor Green

# ---- Apply hardening ----
Write-Host "`nApplying OWA hardening settings..." -ForegroundColor Yellow

Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default `
    -LinkedInEnabled $false `
    -FacebookEnabled $false `
    -AdditionalStorageProvidersAvailable $false `
    -SaveAttachmentsToCloudEnabled $false `
    -PersonalAccountCalendarsEnabled $false `
    -DirectFileAccessOnPublicComputersEnabled $false `
    -WacViewingOnPublicComputersEnabled $false `
    -AccountTransferEnabled $false

Write-Host "✅ OWA policy hardening applied." -ForegroundColor Green

# ---- Verify changes ----
Write-Host "`nVerifying changes..." -ForegroundColor Yellow
Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default | 
Select-Object LinkedInEnabled, FacebookEnabled, AdditionalStorageProvidersAvailable,
    SaveAttachmentsToCloudEnabled, PersonalAccountCalendarsEnabled,
    DirectFileAccessOnPublicComputersEnabled, AccountTransferEnabled |
Format-List
