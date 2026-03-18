# PowerShell Script to Push Files to GitHub Repository
# No Git installation required - uses GitHub API directly

param(
    [string]$Token
)

Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "UPLOAD FILES TO GITHUB" -ForegroundColor Green
Write-Host "========================================================================`n" -ForegroundColor Green

# Get token if not provided
if (-not $Token) {
    Write-Host "Get your GitHub Personal Access Token:" -ForegroundColor Yellow
    Write-Host "1. Go to: https://github.com/settings/tokens/new" -ForegroundColor Cyan
    Write-Host "2. Check 'repo' scope" -ForegroundColor Cyan
    Write-Host "3. Generate and copy the token`n" -ForegroundColor Cyan
    $Token = Read-Host "Paste your GitHub Personal Access Token"
}

# Repository details
$REPO_OWNER = "Adwitiya13"
$REPO_NAME = "semester-6-project-"
$BRANCH = "main"

# Headers for API requests
$headers = @{
    "Authorization" = "token $Token"
    "Accept" = "application/vnd.github.v3+json"
    "Content-Type" = "application/json"
}

# Project directory
$projectDir = "c:\Users\Adwitiya Koley\OneDrive\Desktop\Vulnerability tool\Website-Vulnerability-Analyzer-main"
Set-Location $projectDir

Write-Host "[*] Repository: https://github.com/$REPO_OWNER/$REPO_NAME" -ForegroundColor Cyan
Write-Host "[*] Branch: $BRANCH" -ForegroundColor Cyan
Write-Host "[*] Uploading files...`n" -ForegroundColor Cyan

$uploadedCount = 0
$failedCount = 0

# Function to upload a file
function Upload-FileToGitHub {
    param(
        [string]$filePath,
        [string]$repoPath
    )
    
    try {
        # Skip if file doesn't exist
        if (-not (Test-Path $filePath)) {
            return
        }
        
        # Read and encode file
        $fileContent = [System.IO.File]::ReadAllBytes($filePath)
        $base64Content = [System.Convert]::ToBase64String($fileContent)
        
        # API endpoint
        $apiUri = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/contents/$repoPath"
        
        # Check if file exists (to get SHA for update)
        $sha = $null
        try {
            $existingResponse = Invoke-RestMethod -Uri $apiUri -Method Get -Headers $headers -ErrorAction SilentlyContinue
            $sha = $existingResponse.sha
        } catch {
            # File doesn't exist yet, which is fine
        }
        
        # Prepare commit message
        $commitMsg = "Add $repoPath"
        
        # Build request body
        $body = @{
            message = $commitMsg
            content = $base64Content
            branch = $BRANCH
        }
        
        if ($sha) {
            $body["sha"] = $sha
        }
        
        $jsonBody = $body | ConvertTo-Json -Depth 10
        
        # Upload file via API
        $response = Invoke-RestMethod -Uri $apiUri -Method Put -Headers $headers -Body $jsonBody
        
        Write-Host "[✓] $repoPath" -ForegroundColor Green
        $script:uploadedCount++
        return $true
        
    } catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -like "*Bad credentials*") {
            Write-Host "[✗] AUTHENTICATION FAILED - Invalid token" -ForegroundColor Red
            Write-Host "    Get a new token at: https://github.com/settings/tokens/new" -ForegroundColor Yellow
            exit 1
        } else {
            Write-Host "[✗] $repoPath - Error: $($errorMsg.Substring(0, 60))" -ForegroundColor Red
            $script:failedCount++
        }
        return $false
    }
}

# Define files to upload
$filesToUpload = @(
    # Main application
    @{ local = "app.py"; remote = "app.py" }
    
    # Python modules
    @{ local = "crypto_toolkit.py"; remote = "crypto_toolkit.py" }
    @{ local = "password_analyzer.py"; remote = "password_analyzer.py" }
    @{ local = "network_scanner.py"; remote = "network_scanner.py" }
    @{ local = "file_analyzer.py"; remote = "file_analyzer.py" }
    @{ local = "grc_engine.py"; remote = "grc_engine.py" }
    @{ local = "risk_scorer.py"; remote = "risk_scorer.py" }
    @{ local = "report_generator.py"; remote = "report_generator.py" }
    @{ local = "otp_sharing.py"; remote = "otp_sharing.py" }
    @{ local = "Website_Analyzer_Advanced.py"; remote = "Website_Analyzer_Advanced.py" }
    @{ local = "Website_Analyzer.py"; remote = "Website_Analyzer.py" }
    
    # Documentation
    @{ local = "README_WEB.md"; remote = "README_WEB.md" }
    @{ local = "README.md"; remote = "README.md" }
    @{ local = "README_ADVANCED.md"; remote = "README_ADVANCED.md" }
    @{ local = "QUICKSTART.md"; remote = "QUICKSTART.md" }
    
    # Config files
    @{ local = "config.yml"; remote = "config.yml" }
    @{ local = "config_example.yml"; remote = "config_example.yml" }
)

# Upload main files
Write-Host "=== Uploading Python & Documentation Files ===" -ForegroundColor Yellow
foreach ($file in $filesToUpload) {
    Upload-FileToGitHub -filePath $file.local -repoPath $file.remote
    Start-Sleep -Milliseconds 300  # Rate limiting
}

# Upload HTML templates
Write-Host "`n=== Uploading HTML Templates ===" -ForegroundColor Yellow
$templates = @(
    "base.html", "index.html", "demo.html", "password.html", 
    "analyzer.html", "crypto.html", "file.html", "risk.html", 
    "compliance.html", "reports.html"
)

foreach ($template in $templates) {
    $localPath = "templates\$template"
    $remotePath = "templates/$template"
    Upload-FileToGitHub -filePath $localPath -repoPath $remotePath
    Start-Sleep -Milliseconds 300
}

# Summary
Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "UPLOAD COMPLETE" -ForegroundColor Green
Write-Host "========================================================================`n" -ForegroundColor Green

Write-Host "✓ Successfully uploaded: $uploadedCount files" -ForegroundColor Green
if ($failedCount -gt 0) {
    Write-Host "✗ Failed: $failedCount files" -ForegroundColor Red
}

Write-Host "`n[*] Repository: https://github.com/$REPO_OWNER/$REPO_NAME" -ForegroundColor Cyan
Write-Host "`n========================================================================`n" -ForegroundColor Green

Read-Host "Press Enter to close"
