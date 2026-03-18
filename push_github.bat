@echo off
REM Simple batch script to push files to GitHub using curl
REM Make sure you have your GitHub token ready

echo.
echo ========================================================================
echo PUSHING FILES TO GITHUB
echo ========================================================================
echo.

set /p GITHUB_TOKEN="Enter your GitHub Personal Access Token: "
set REPO_OWNER=Adwitiya13
set REPO_NAME=semester-6-project-
set BRANCH=main
set PROJECT_DIR=c:\Users\Adwitiya Koley\OneDrive\Desktop\Vulnerability tool\Website-Vulnerability-Analyzer-main

echo.
echo [*] Project Directory: %PROJECT_DIR%
echo [*] Repository: https://github.com/%REPO_OWNER%/%REPO_NAME%
echo.

REM List of files to push
cd /d "%PROJECT_DIR%"

echo [*] Uploading files...

REM Upload app.py
echo [*] Uploading app.py...
powershell -Command "^
$token = '%GITHUB_TOKEN%'; ^
$content = [System.IO.File]::ReadAllBytes('app.py'); ^
$base64 = [System.Convert]::ToBase64String($content); ^
$headers = @{'Authorization'='token ' + $token; 'Accept'='application/vnd.github.v3+json'}; ^
$body = @{'message'='Add app.py'; 'content'=$base64; 'branch'='%BRANCH%'} | ConvertTo-Json; ^
try { ^
  $response = Invoke-RestMethod -Uri 'https://api.github.com/repos/%REPO_OWNER%/%REPO_NAME%/contents/app.py' -Method Get -Headers $headers -ErrorAction SilentlyContinue; ^
  if ($response) { $body = ($body | ConvertFrom-Json); $body | Add-Member -NotePropertyName 'sha' -NotePropertyValue $response.sha; $body = $body | ConvertTo-Json; }; ^
  $result = Invoke-RestMethod -Uri 'https://api.github.com/repos/%REPO_OWNER%/%REPO_NAME%/contents/app.py' -Method Put -Headers $headers -Body $body; ^
  Write-Host '[OK] app.py uploaded'; ^
} catch { Write-Host '[ERROR] ' $_.Exception.Message; ^
}"

REM Upload README_WEB.md
echo [*] Uploading README_WEB.md...
powershell -Command "^
$token = '%GITHUB_TOKEN%'; ^
$content = [System.IO.File]::ReadAllBytes('README_WEB.md'); ^
$base64 = [System.Convert]::ToBase64String($content); ^
$headers = @{'Authorization'='token ' + $token; 'Accept'='application/vnd.github.v3+json'}; ^
$body = @{'message'='Add README_WEB.md'; 'content'=$base64; 'branch'='%BRANCH%'} | ConvertTo-Json; ^
try { ^
  $response = Invoke-RestMethod -Uri 'https://api.github.com/repos/%REPO_OWNER%/%REPO_NAME%/contents/README_WEB.md' -Method Get -Headers $headers -ErrorAction SilentlyContinue; ^
  if ($response) { $body = ($body | ConvertFrom-Json); $body | Add-Member -NotePropertyName 'sha' -NotePropertyValue $response.sha; $body = $body | ConvertTo-Json; }; ^
  $result = Invoke-RestMethod -Uri 'https://api.github.com/repos/%REPO_OWNER%/%REPO_NAME%/contents/README_WEB.md' -Method Put -Headers $headers -Body $body; ^
  Write-Host '[OK] README_WEB.md uploaded'; ^
} catch { Write-Host '[ERROR] ' $_.Exception.Message; ^
}"

REM Upload all security modules
for %%F in (crypto_toolkit.py password_analyzer.py network_scanner.py file_analyzer.py grc_engine.py risk_scorer.py report_generator.py otp_sharing.py Website_Analyzer_Advanced.py Website_Analyzer.py) do (
  echo [*] Uploading %%F...
  powershell -Command "^
$file = '%%F'; ^
$token = '%GITHUB_TOKEN%'; ^
$content = [System.IO.File]::ReadAllBytes($file); ^
$base64 = [System.Convert]::ToBase64String($content); ^
$headers = @{'Authorization'='token ' + $token; 'Accept'='application/vnd.github.v3+json'}; ^
$body = @{'message'='Add ' + $file; 'content'=$base64; 'branch'='%BRANCH%'} | ConvertTo-Json; ^
try { ^
  $response = Invoke-RestMethod -Uri ('https://api.github.com/repos/%REPO_OWNER%/%REPO_NAME%/contents/' + $file) -Method Get -Headers $headers -ErrorAction SilentlyContinue; ^
  if ($response) { $body = ($body | ConvertFrom-Json); $body | Add-Member -NotePropertyName 'sha' -NotePropertyValue $response.sha; $body = $body | ConvertTo-Json; }; ^
  $result = Invoke-RestMethod -Uri ('https://api.github.com/repos/%REPO_OWNER%/%REPO_NAME%/contents/' + $file) -Method Put -Headers $headers -Body $body; ^
  Write-Host '[OK] ' $file ' uploaded'; ^
} catch { Write-Host '[ERROR] ' $_.Exception.Message; ^
}"
)

REM Upload templates
echo [*] Uploading HTML templates...
for %%F in (templates\base.html templates\index.html templates\demo.html templates\password.html templates\analyzer.html templates\crypto.html templates\file.html templates\risk.html templates\compliance.html templates\reports.html) do (
  echo [*] Uploading %%F...
  powershell -Command "^
$file = '%%F'; ^
$token = '%GITHUB_TOKEN%'; ^
$content = [System.IO.File]::ReadAllBytes($file); ^
$base64 = [System.Convert]::ToBase64String($content); ^
$path = $file.Replace('\', '/'); ^
$headers = @{'Authorization'='token ' + $token; 'Accept'='application/vnd.github.v3+json'}; ^
$body = @{'message'='Add ' + $path; 'content'=$base64; 'branch'='%BRANCH%'} | ConvertTo-Json; ^
try { ^
  $response = Invoke-RestMethod -Uri ('https://api.github.com/repos/%REPO_OWNER%/%REPO_NAME%/contents/' + $path) -Method Get -Headers $headers -ErrorAction SilentlyContinue; ^
  if ($response) { $body = ($body | ConvertFrom-Json); $body | Add-Member -NotePropertyName 'sha' -NotePropertyValue $response.sha; $body = $body | ConvertTo-Json; }; ^
  $result = Invoke-RestMethod -Uri ('https://api.github.com/repos/%REPO_OWNER%/%REPO_NAME%/contents/' + $path) -Method Put -Headers $headers -Body $body; ^
  Write-Host '[OK] ' $file ' uploaded'; ^
} catch { Write-Host '[ERROR] ' $_.Exception.Message; ^
}"
)

echo.
echo ========================================================================
echo [OK] Upload Complete!
echo [*] Check your repository: https://github.com/%REPO_OWNER%/%REPO_NAME%
echo ========================================================================
echo.
pause
