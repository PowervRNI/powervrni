# PowervRNI Publishing:
#
# - Generate a new manifest
# - Publish it to PowerShell Gallery
#
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 1.0

param (
  # Required API key to upload to PowerShell Gallery.
  [Parameter (Mandatory = $true)]
  [string]$NuGetApiKey
)

# Source the Include.ps1 file for settings
. ./Include.ps1

# Append the current build number on the version number. For this, we need git.
# The build number is correlated on how many commits there are.

# Check if we have git
try { if (Get-Command git) { <# we have git, so continue! #> } }
catch { throw "For this script to run, we need git. I couldn't find git." }

# Get build number
$BuildNumber = (git log --oneline).Count
# Format version number
$PowervRNI_Version = $PowervRNI_Version + '.' + $BuildNumber.ToString().Trim()
# Test version
if (-not ($PowervRNI_Version -as [version])) {
  throw "$PowervRNI_Version is not a valid version number. Try again."
}
# Add the version to the manifest options
$Manifest_Common.Add("ModuleVersion", $PowervRNI_Version)

# Get current working directory
$currentPath = split-path $MyInvocation.MyCommand.Path

# Generate new manifest file
New-ModuleManifest -Path "$currentPath/../PowervRNI.psd1" -PowerShellVersion '6.0' @Manifest_Common
# Convert to UTF8
$content = Get-Content "$currentPath/../PowervRNI.psd1"
[System.IO.File]::WriteAllLines("$currentPath/../PowervRNI.psd1", $content)

# Copy module file to publish directory
Copy-Item -Path "$currentPath/../PowervRNI.psm1" "$currentPath/psgallery/PowervRNI/"
# Copy manifest file to publish directory
Copy-Item -Path "$currentPath/../PowervRNI.psd1" "$currentPath/psgallery/PowervRNI/"

Publish-Module -NuGetApiKey $NuGetApiKey -Path "$currentPath/psgallery/PowervRNI" -ReleaseNotes $Manifest_Common.ReleaseNotes

Write-Host -ForegroundColor Yellow "PowervRNI $PowervRNI_Version is now published to the PowerShell Gallery! Also push the new files to GitHub."
