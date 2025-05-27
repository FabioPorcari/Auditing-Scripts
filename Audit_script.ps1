# Script per tracciare l'avvio di script .ps1 da parte di un utente specifico IN TEMPO REALE
# con logging cumulativo, giornaliero, postazione, IP locale, de-duplicazione e auto-esclusione.
# VERSIONE FINALE PULITA

param (
    [Parameter(Mandatory=$true)]
    [string]$NomeUtenteDaMonitorare
)

# --- Ottieni il nome di questo script di monitoraggio ---
$NomeFileScriptMonitoraggio = $MyInvocation.MyCommand.Name

# --- Cache per de-duplicazione avvii recenti ---
$cacheAvviiRecentiLocale = @{} # Non $script: scope, passata via MessageData
$intervalloDeDuplicazioneSecondiLocale = 2 # Intervallo in secondi

# --- Verifica dei privilegi di Amministratore ---
$ident = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($ident)

if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Questo script richiede privilegi di Amministratore. Per favore, rieseguilo da una console PowerShell avviata come Amministratore."
    Read-Host "Premi Invio per uscire."
    exit 1
}
Write-Host "Privilegi di Amministratore confermati." -ForegroundColor Green

# --- Definizione Path per il Logging ---
$NomeCartellaLog = "tracciamento_script_$NomeUtenteDaMonitorare"
$PercorsoBase = "C:\"
$PercorsoCompletoCartellaLog = Join-Path -Path $PercorsoBase -ChildPath $NomeCartellaLog

if (-not (Test-Path $PercorsoCompletoCartellaLog)) {
    try {
        New-Item -ItemType Directory -Path $PercorsoCompletoCartellaLog -ErrorAction Stop | Out-Null
        Write-Host "Cartella di log creata/verificata: $PercorsoCompletoCartellaLog" -ForegroundColor DarkCyan
    } catch {
        Write-Error "Impossibile creare la cartella di log: $($_.Exception.Message). Script interrotto."
        Read-Host "Premi Invio per uscire."
        exit 1 
    }
}

$PercorsoFileLogCumulativo = Join-Path -Path $PercorsoCompletoCartellaLog -ChildPath "tracciamento_completo_$($NomeUtenteDaMonitorare).txt"

Write-Host "Lo script di monitoraggio '$NomeFileScriptMonitoraggio' ignorerà la propria esecuzione nel log." -ForegroundColor Cyan
Write-Host "Log duplicati per lo stesso script entro $($intervalloDeDuplicazioneSecondiLocale) secondi verranno ignorati." -ForegroundColor Cyan
Write-Host "I log cumulativi verranno salvati in: $PercorsoFileLogCumulativo" -ForegroundColor Cyan 
Write-Host "I log giornalieri verranno salvati in $PercorsoCompletoCartellaLog con il formato 'tracciamento_script_NOMEUTENTE_YYYY-MM-DD.txt'" -ForegroundColor Cyan
Write-Host "Inizio monitoraggio in tempo reale per l'utente: $NomeUtenteDaMonitorare" -ForegroundColor Yellow
Write-Host "Premi CTRL+C per interrompere il monitoraggio." -ForegroundColor Yellow

# --- 1. Verifica e Abilitazione dell'Auditing ---
Write-Host "Verifica e abilitazione dell'auditing 'Process Creation' usando il GUID..." -ForegroundColor Cyan
$ProcessCreationSubCategoryGUID = "{0CCE922B-69AE-11D9-BED3-505054503030}"
$AuditPolicyProcessOutput = auditpol /get /subcategory:$ProcessCreationSubCategoryGUID /r
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Impossibile ottenere stato audit policy 'Process Creation' (GUID: $ProcessCreationSubCategoryGUID)."
    Write-Host "Tentativo di impostare auditing 'Process Creation'..."
    auditpol /set /subcategory:$ProcessCreationSubCategoryGUID /success:enable /failure:enable
    if ($LASTEXITCODE -ne 0) { Write-Warning "Comando 'auditpol /set' per 'Process Creation' (GUID) fallito." }
    else { Write-Host "'Process Creation' auditing (GUID) dovrebbe essere abilitato." -ForegroundColor Green }
} else {
    if ($AuditPolicyProcessOutput -match "$ProcessCreationSubCategoryGUID,Successo e fallimento" -or $AuditPolicyProcessOutput -match "$ProcessCreationSubCategoryGUID,Successo") {
        Write-Host "'Process Creation' auditing (GUID) già configurato." -ForegroundColor Green
    } else { 
        Write-Host "Abilitazione auditing 'Process Creation' (GUID)..."
        auditpol /set /subcategory:$ProcessCreationSubCategoryGUID /success:enable /failure:enable
        if ($LASTEXITCODE -ne 0) { Write-Warning "Comando 'auditpol /set' per 'Process Creation' (GUID) fallito."}
        else { Write-Host "'Process Creation' auditing (GUID) abilitato." -ForegroundColor Green }
    }
}
Write-Host "--- Configurazione Auditing Completata ---" -ForegroundColor Cyan; Write-Host ""

# --- 2. Preparazione dei dati per l'Action Block ---
$EventActionData = @{
    NomeUtenteDaMonitorare     = $NomeUtenteDaMonitorare
    PercorsoCartellaLog        = $PercorsoCompletoCartellaLog 
    PercorsoFileLogCumulativo  = $PercorsoFileLogCumulativo  
    NomeFileScriptMonitoraggio = $NomeFileScriptMonitoraggio
    CacheAvvii                 = $cacheAvviiRecentiLocale          
    IntervalloDeDup            = $intervalloDeDuplicazioneSecondiLocale 
}

# --- 3. Registrazione dell'Event Subscriber ---
Write-Host "Registrazione event subscriber per PowerShell Event ID 4104..."
Unregister-Event -SourceIdentifier "PowerShellScriptExecuted" -ErrorAction SilentlyContinue

# --- INIZIO BLOCCO $Action ---
$Action = {
    $DatiPassati = $event.MessageData 
    $Evento = $event.SourceEventArgs.EventRecord

    if ($Evento.Id -ne 4104) { return }
    
    $UserSid = $Evento.UserId
    $NomeUtenteSempliceEvento = "Sconosciuto"
    if ($UserSid) { 
        try { $NomeUtenteSempliceEvento = (New-Object System.Security.Principal.SecurityIdentifier($UserSid)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1] } catch {} 
    }

    if ($NomeUtenteSempliceEvento -eq $DatiPassati.NomeUtenteDaMonitorare) {
        $ScriptBlockText = $null; $ScriptPath = $null 
        if ($Evento.Properties.Count -ge 3) { $ScriptBlockText = $Evento.Properties[2].Value }
        if ($Evento.Properties.Count -ge 5) { $ScriptPath = $Evento.Properties[4].Value }
        
        $NomeScriptIdentificato = $null; $TipoRilevamento = ""
        if ($ScriptPath -and ($ScriptPath -like "*.ps1" -or $ScriptPath -like "*.psm1")) {
            $NomeScriptIdentificato = $ScriptPath; $TipoRilevamento = "Path Diretto"
        } elseif ($ScriptBlockText) {
            $MatchedPath = $ScriptBlockText | Select-String -Pattern "([a-zA-Z]:\\(?:[^\\/:*?""<>|\r\n]+\\)*[^\\/:*?""<>|\r\n]+\.(?:ps1|psm1)|powershell\.exe.*?\s([^\s]+\.(?:ps1|psm1)))" -AllMatches -EA SilentlyContinue
            if ($MatchedPath.Matches.Count -gt 0) {
                $NomeScriptIdentificato = if ($MatchedPath.Matches[0].Groups[2].Success) { $MatchedPath.Matches[0].Groups[2].Value } else { $MatchedPath.Matches[0].Groups[1].Value }
                $TipoRilevamento = "Contenuto Blocco (Regex Specifica)"
            } else {
                 $ScriptMatchGenerico = $ScriptBlockText | Select-String -Pattern "([a-zA-Z0-9\s_\\:\-\.\$]+\.(?:ps1|psm1))" -EA SilentlyContinue
                 if ($ScriptMatchGenerico) { $NomeScriptIdentificato = $ScriptMatchGenerico.Matches.Value | Select-Object -First 1; if ($NomeScriptIdentificato) {$TipoRilevamento = "Contenuto Blocco (Regex Generica)"} }
            }
        }
        
        if ($NomeScriptIdentificato) {
            $NomeFileNormalizzato = try { [System.IO.Path]::GetFileName($NomeScriptIdentificato).ToLowerInvariant() } catch { $NomeScriptIdentificato.ToLowerInvariant() }
            
            if ($NomeFileNormalizzato -ne $DatiPassati.NomeFileScriptMonitoraggio.ToLowerInvariant()) {
                $LoggareQuestoEvento = $true 
                $OraAttualeEvento = $Evento.TimeCreated
                
                $CacheLocaleAzione = $DatiPassati.CacheAvvii 
                $IntervalloDeDupAzione = $DatiPassati.IntervalloDeDup

                if ($CacheLocaleAzione.ContainsKey($NomeFileNormalizzato)) {
                    $TimestampUltimoLog = $CacheLocaleAzione[$NomeFileNormalizzato]
                    if (($OraAttualeEvento - $TimestampUltimoLog).TotalSeconds -lt $IntervalloDeDupAzione) {
                        $LoggareQuestoEvento = $false
                    }
                }

                if ($LoggareQuestoEvento) {
                    $CacheLocaleAzione[$NomeFileNormalizzato] = $OraAttualeEvento 
                    
                    $Postazione = $Evento.MachineName
                    $IpString = "N/D" 
                    try { $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -EA SilentlyContinue | Select-Object -ExpandProperty IPAddress; if ($ipAddresses) { $IpString = $ipAddresses -join '; ' } } catch {}
                    $DataOraEventoString = $Evento.TimeCreated.ToString("dd/MM/yyyy HH:mm:ss")
                    $MessaggioLog = "$($DatiPassati.NomeUtenteDaMonitorare) ha avviato script '$NomeScriptIdentificato' da '$Postazione' (IP Locale: $IpString) data $DataOraEventoString (Rilevato: $TipoRilevamento, ID: $($Evento.Id))"
                    
                    Write-Host $MessaggioLog -ForegroundColor Green 
                    try { Add-Content -Path $DatiPassati.PercorsoFileLogCumulativo -Value $MessaggioLog -Encoding UTF8 -ErrorAction Stop } 
                    catch { Write-Warning "Errore scrittura log cumulativo '$($DatiPassati.PercorsoFileLogCumulativo)': $($_.Exception.Message)" }
                    $DataFileGiornaliero = $Evento.TimeCreated.ToString("yyyy-MM-dd") 
                    $NomeFileGiornaliero = "tracciamento_script_$($DatiPassati.NomeUtenteDaMonitorare)_$($DataFileGiornaliero).txt"
                    $PercorsoFileGiornaliero = Join-Path -Path $DatiPassati.PercorsoCartellaLog -ChildPath $NomeFileGiornaliero
                    try { Add-Content -Path $PercorsoFileGiornaliero -Value $MessaggioLog -Encoding UTF8 -ErrorAction Stop }
                    catch { Write-Warning "Errore scrittura log giornaliero '$($PercorsoFileGiornaliero)': $($_.Exception.Message)" }
                }
            }
        }
    }
} # Fine Blocco Action
# --- FINE BLOCCO $Action ---

$PSEventJob = $null; $Watcher = $null
try {
    $Watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher("Microsoft-Windows-PowerShell/Operational")
    $Watcher.Enabled = $true
    $PSEventJob = Register-ObjectEvent -InputObject $Watcher -EventName "EventRecordWritten" -SourceIdentifier "PowerShellScriptExecuted" -Action $Action -MessageData $EventActionData -ErrorAction Stop
    if ($null -eq $PSEventJob) { Write-Error "Registrazione event job fallita."; if ($Watcher) { $Watcher.Enabled = $false; $Watcher.Dispose() }; exit 1 }
    Write-Host "Monitoraggio attivo. Job ID: $($PSEventJob.Id), Stato: $($PSEventJob.State). Attesa eventi..." -ForegroundColor Green
} catch { Write-Error "Errore subscriber: $($_.Exception.Message)"; if ($Watcher) { $Watcher.Enabled = $false; $Watcher.Dispose() }; exit 1 }

try { do { Wait-Event -SourceIdentifier "PowerShellScriptExecuted" -Timeout 1 } while ($true) }
catch [System.Management.Automation.ActionPreferenceStopException] { Write-Host "Interruzione monitoraggio (CTRL+C)." -ForegroundColor Yellow }
catch { Write-Error "Errore loop monitoraggio: $($_.Exception.Message)" }
finally {
    Write-Host "Rimozione subscriber e pulizia..." -ForegroundColor Yellow
    if ($Watcher) { $Watcher.Enabled = $false; $Watcher.Dispose() }
    if ($PSEventJob) { Unregister-Event -SourceIdentifier "PowerShellScriptExecuted" -EA SilentlyContinue; Remove-Job $PSEventJob -Force -EA SilentlyContinue }
    else { Unregister-Event -SourceIdentifier "PowerShellScriptExecuted" -EA SilentlyContinue } 
    Write-Host "Script terminato."
}