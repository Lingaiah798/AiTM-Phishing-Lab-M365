# ============================================================
# revoke-sessions.ps1
# AiTM Phishing Lab - Compromised Account Session Revocation
# ⚠️  WARNING: This will sign the user out of ALL active sessions
# ============================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$UserEmail
)

Write-Host "`n⚠️  Revoking all sessions for: $UserEmail" -ForegroundColor Red
Write-Host "This will immediately sign the user out of all devices and apps.`n"

# Revoke all refresh tokens via Microsoft Graph (modern method)
$confirm = Read-Host "Type YES to confirm"
if ($confirm -eq "YES") {
    
    # Method 1: Via Azure AD PowerShell
    $user = Get-AzureADUser -Filter "UserPrincipalName eq '$UserEmail'"
    Revoke-AzureADUserAllRefreshToken -ObjectId $user.ObjectId
    Write-Host "✅ All refresh tokens revoked." -ForegroundColor Green

    # Method 2: Also disable sign-in temporarily
    Set-AzureADUser -ObjectId $user.ObjectId -AccountEnabled $false
    Write-Host "✅ Account sign-in disabled." -ForegroundColor Green

    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Reset the user's password immediately"
    Write-Host "2. Investigate inbox rules and forwarding"
    Write-Host "3. Review audit logs for post-compromise activity"
    Write-Host "4. Re-enable account after password reset: Set-AzureADUser -ObjectId <id> -AccountEnabled `$true"
} else {
    Write-Host "❌ Cancelled." -ForegroundColor Yellow
}
