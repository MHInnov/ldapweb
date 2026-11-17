# Installation d'Arbor comme service Windows (PowerShell en administrateur).
# Prérequis : binaire compilé avec `cargo build --release --features windows-service`.
param(
    [string]$Source = ".\target\release\arbor.exe",
    [string]$InstallDir = "$env:ProgramFiles\Arbor",
    [string]$DataDir = "$env:ProgramData\Arbor"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
Copy-Item $Source "$InstallDir\arbor.exe" -Force
if (-not (Test-Path "$DataDir\arbor.toml")) {
    & "$InstallDir\arbor.exe" init-config "$DataDir\arbor.toml"
    Write-Host "Configuration d'exemple créée : $DataDir\arbor.toml — adaptez-la avant de démarrer le service."
}
# Le compte du service doit pouvoir lire la configuration et écrire dans data_dir.
icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
sc.exe create Arbor binPath= "`"$InstallDir\arbor.exe`" -c `"$DataDir\arbor.toml`" service" start= auto DisplayName= "Arbor - administration d'annuaire"
sc.exe description Arbor "Console web d'administration LDAP / Active Directory et services connexes"
sc.exe failure Arbor reset= 86400 actions= restart/5000/restart/5000/restart/30000
New-NetFirewallRule -DisplayName "Arbor (HTTPS)" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow | Out-Null
Write-Host "Service créé. Démarrage : sc.exe start Arbor — journaux : $DataDir\data\arbor.log"
