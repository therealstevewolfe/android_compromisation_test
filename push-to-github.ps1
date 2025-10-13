#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Push Android Forensic Suite to GitHub
.DESCRIPTION
    This script helps you push the Android Forensic Analysis Suite to your GitHub repository.
#>

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "     Android Forensic Suite - GitHub Push Helper" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Follow these steps to push your repository to GitHub:" -ForegroundColor Yellow
Write-Host ""

Write-Host "Step 1: Create a new repository on GitHub" -ForegroundColor Green
Write-Host "  1. Go to https://github.com/new"
Write-Host "  2. Name your repository (e.g., 'android-forensic-suite')"
Write-Host "  3. Set it to Public or Private as desired"
Write-Host "  4. DON'T initialize with README, .gitignore, or license (we already have them)"
Write-Host "  5. Click 'Create repository'"
Write-Host ""

Write-Host "Step 2: Copy your repository URL" -ForegroundColor Green
Write-Host "  After creating, GitHub will show you the repository URL."
Write-Host "  It looks like: https://github.com/YOUR_USERNAME/android-forensic-suite.git"
Write-Host ""

$repoUrl = Read-Host "Enter your GitHub repository URL"

if ($repoUrl) {
    Write-Host ""
    Write-Host "Step 3: Adding remote and pushing..." -ForegroundColor Green
    
    # Check if remote origin already exists
    $existingRemote = $null
    try {
        $existingRemote = git remote get-url origin 2>$null
    } catch {
        # Remote doesn't exist
    }
    
    if ($existingRemote) {
        Write-Host "Updating existing remote origin..." -ForegroundColor Yellow
        git remote set-url origin $repoUrl
    } else {
        Write-Host "Adding remote origin..." -ForegroundColor Yellow
        git remote add origin $repoUrl
    }
    
    Write-Host "Pushing to GitHub..." -ForegroundColor Yellow
    git push -u origin main
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Success! Your repository has been pushed to GitHub!" -ForegroundColor Green
        $repoWebUrl = $repoUrl -replace '\.git$', ''
        Write-Host "You can view it at: $repoWebUrl" -ForegroundColor Cyan
        
        Write-Host ""
        Write-Host "Next Steps:" -ForegroundColor Yellow
        Write-Host "  1. Go to your repository's Settings > Actions > General"
        Write-Host "  2. Ensure 'Actions permissions' is set to allow workflows"
        Write-Host "  3. You can manually trigger the workflow from the Actions tab"
        Write-Host "  4. Consider adding repository topics: android, forensics, security, powershell"
        Write-Host "  5. Add a description to your repository for better discoverability"
        Write-Host ""
        
        Write-Host "Security Recommendations:" -ForegroundColor Yellow
        Write-Host "  - Keep your repository private if analyzing sensitive devices"
        Write-Host "  - Use GitHub Secrets for Slack webhook URL if using notifications"
        Write-Host "  - Review logs before uploading to ensure no sensitive data"
        Write-Host ""
    } else {
        Write-Host ""
        Write-Host "Push failed. Common issues:" -ForegroundColor Red
        Write-Host "  - Authentication: You may need to use a Personal Access Token"
        Write-Host "  - Branch name: Try 'git branch -M main' if your branch is named differently"
        Write-Host "  - Permissions: Ensure you have write access to the repository"
        Write-Host ""
        
        Write-Host "For authentication, create a Personal Access Token:" -ForegroundColor Yellow
        Write-Host "  1. Go to GitHub Settings > Developer settings > Personal access tokens"
        Write-Host "  2. Generate new token with 'repo' scope"
        Write-Host "  3. Use the token as your password when prompted"
        Write-Host ""
    }
} else {
    Write-Host ""
    Write-Host "No URL provided. Please run the script again when ready." -ForegroundColor Red
    Write-Host ""
    Write-Host "Alternatively, you can run these commands manually:" -ForegroundColor Yellow
    Write-Host "  git remote add origin YOUR_REPO_URL" -ForegroundColor Cyan
    Write-Host "  git push -u origin main" -ForegroundColor Cyan
    Write-Host ""
}

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""
