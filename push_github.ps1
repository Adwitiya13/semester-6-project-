# Simple PowerShell Script to Push Files to GitHub
# Run this from command prompt: powershell -ExecutionPolicy Bypass -File push_github.ps1

Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "PUSH FILES TO GITHUB" -ForegroundColor Green
Write-Host "========================================================================`n" -ForegroundColor Green

# Get GitHub token
$GITHUB_TOKEN = Read-Host "Enter your GitHub Personal Access Token"
$REPO_OWNER = "Adwitiya13"
$REPO_NAME = "semester-6-project-"
$BRANCH = "main"

$headers = @{
    "Authorization" = "token $GITHUB_TOKEN"
    "Accept" = "application/vnd.github.v3+json"
}

# Project directory
$projectDir = "c:\Users\Adwitiya Koley\OneDrive\Desktop\Vulnerability tool\Website-Vulnerability-Analyzer-main"
Set-Location $projectDir

Write-Host "[*] Repository: https://github.com/$REPO_OWNER/$REPO_NAME" -ForegroundColor Cyan
Write-Host "[*] Uploading files...`n" -ForegroundColor Cyan

$uploadedFiles = @()
$failedFiles = @()

# Function to upload a file
function Upload-File {
    param(
        [string]$filePath,
        [string]$githubPath
    )
    
    try {
        # Read file content
        $fileContent = [System.IO.File]::ReadAllBytes($filePath)
        $base64Content = [System.Convert]::ToBase64String($fileContent)
        
        # Prepare request
        $uri = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/contents/$githubPath"
        
        # Check if file exists
        $getResponse = @{
            Uri = $uri
            Method = "Get"
            Headers = $headers
            ErrorAction = "SilentlyContinue"
        }
        
        try {
            $existingFile = Invoke-RestMethod @getResponse
            $sha = $existingFile.sha
        } catch {
            $sha = $null
        }
        
        # Prepare body
        $body = @{
            message = "Add $githubPath"
            content = $base64Content
            branch = $BRANCH
        }
        
        if ($sha) {
            $body["sha"] = $sha
        }
        
        $jsonBody = $body | ConvertTo-Json
        
        # Upload file
        $putResponse = @{
            Uri = $uri
            Method = "Put"
            Headers = $headers
            Body = $jsonBody
            ContentType = "application/json"
        }
        
        $result = Invoke-RestMethod @putResponse
        Write-Host "[OK] $githubPath" -ForegroundColor Green
        $script:uploadedFiles += $githubPath
        
    } catch {
        Write-Host "[ERROR] $githubPath - $($_.Exception.Message.Substring(0, 50))" -ForegroundColor Red
        $script:failedFiles += $githubPath
    }
}

# Upload main Python files
Write-Host "=== Python Files ===" -ForegroundColor Yellow
$pythonFiles = @(
    "app.py",
    "crypto_toolkit.py",
    "password_analyzer.py",
    "network_scanner.py",
    "file_analyzer.py",
    "grc_engine.py",
    "risk_scorer.py",
    "report_generator.py",
    "otp_sharing.py",
    "Website_Analyzer_Advanced.py",
    "Website_Analyzer.py"
)

foreach ($file in $pythonFiles) {
    if (Test-Path $file) {
        Upload-File $file $file
        Start-Sleep -Milliseconds 500
    }
}

# Upload documentation
Write-Host "`n=== Documentation ===" -ForegroundColor Yellow
$docFiles = @("README_WEB.md", "README.md", "QUICKSTART.md", "README_ADVANCED.md")

foreach ($file in $docFiles) {
    if (Test-Path $file) {
        Upload-File $file $file
        Start-Sleep -Milliseconds 500
    }
}

# Upload config files
Write-Host "`n=== Config Files ===" -ForegroundColor Yellow
$configFiles = @("config.yml", "config_example.yml")

foreach ($file in $configFiles) {
    if (Test-Path $file) {
        Upload-File $file $file
        Start-Sleep -Milliseconds 500
    }
}

# Upload HTML templates
Write-Host "`n=== HTML Templates ===" -ForegroundColor Yellow
$templateFiles = @(
    "templates/base.html",
    "templates/index.html",
    "templates/demo.html",
    "templates/password.html",
    "templates/analyzer.html",
    "templates/crypto.html",
    "templates/file.html",
    "templates/risk.html",
    "templates/compliance.html",
    "templates/reports.html"
)

foreach ($file in $templateFiles) {
    if (Test-Path $file) {
        $githubPath = $file.Replace('\', '/')
        Upload-File $file $githubPath
        Start-Sleep -Milliseconds 500
    }
}

# Summary
Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "UPLOAD SUMMARY" -ForegroundColor Green
Write-Host "========================================================================`n" -ForegroundColor Green

Write-Host "[OK] Successfully uploaded: $($uploadedFiles.Count) files" -ForegroundColor Green
Write-Host "[ERROR] Failed: $($failedFiles.Count) files" -ForegroundColor Red

if ($uploadedFiles.Count -gt 0) {
    Write-Host "`nUploaded Files:" -ForegroundColor Green
    $uploadedFiles | ForEach-Object { Write-Host "  ✓ $_" -ForegroundColor Green }
}

if ($failedFiles.Count -gt 0) {
    Write-Host "`nFailed Files:" -ForegroundColor Red
    $failedFiles | ForEach-Object { Write-Host "  ✗ $_" -ForegroundColor Red }
}

Write-Host "`n[*] Repository: https://github.com/$REPO_OWNER/$REPO_NAME" -ForegroundColor Cyan
Write-Host "`n========================================================================`n" -ForegroundColor Green

Read-Host "Press Enter to exit"
