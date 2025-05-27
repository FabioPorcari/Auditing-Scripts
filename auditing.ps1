param (
    [string]$InputParam
)

if (-not $InputParam) {
    Write-Host "Uso: auditing.ps1 <nome.exe> oppure <nome utente>"
    exit
}

# === INFORMAZIONI MACCHINA LOCALE (recuperate una sola volta) ===
$localMachineName = $env:COMPUTERNAME
$localIp = "N/D" 
try {
    $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.InterfaceAlias -notlike "Loopback*" -and $_.AddressState -eq 'Preferred' -and $_.PrefixOrigin -ne 'WellKnown'
    }
    if ($ipAddresses) {
        $preferredIp = $ipAddresses | Where-Object { -not ($_.IPAddress -like "169.254.*") } | Select-Object -First 1
        if ($preferredIp) {
            $localIp = $preferredIp.IPAddress
        } elseif ($ipAddresses) {
            $localIp = ($ipAddresses | Select-Object -First 1).IPAddress
        }
    }
} catch {
    $localIp = "N/D (errore recupero IP)"
}
# ================================================================

# === TIMESTAMP DI AVVIO SCRIPT E ULTIMO CONTROLLO EVENTI UTENTE ===
$scriptExecutionStartTime = Get-Date
$lastUserEventCheckTime = $scriptExecutionStartTime # Inizializza all'ora di avvio dello script
# =====================================================================

# Pulizia nome
$sanitizedName = ($InputParam -replace ".exe", "").Trim()
$folderPath = "C:\Processi_$sanitizedName"

# Crea directory principale
if (-not (Test-Path -Path $folderPath)) {
    New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    Write-Host "✅ Directory creata: $folderPath"
} else {
    Write-Host "ℹ️ Directory già presente: $folderPath"
}

# Crea directory cumulativa
$cumulativeFolderPath = "$folderPath\Tutti_i_processi"
if (-not (Test-Path -Path $cumulativeFolderPath)) {
    New-Item -ItemType Directory -Path $cumulativeFolderPath -Force | Out-Null
    Write-Host "✅ Cartella Tutti_i_processi creata: $cumulativeFolderPath"
}

# File di log cumulativo (il nome rimane costante)
$cumulativeLogFile = "$cumulativeFolderPath\processi_completi.txt"

# HashSet per tenere traccia delle istanze di processo già loggate in questa sessione
$loggedProcessInstances = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function LogToFile {
    param ($text, $filePath)
    try {
        $text | Out-File -Append -FilePath $filePath -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Warning "Errore durante la scrittura nel file '$filePath': $($_.Exception.Message)"
    }
}

function LogToConsole {
    param ($text)
    Write-Host $text
}

Write-Host "`nScript in esecuzione continua. Premere Ctrl+C per interrompere."
Write-Host "Avviato il: $($scriptExecutionStartTime.ToString('dd-MM-yyyy HH:mm:ss'))"
Write-Host "Info Macchina Locale: $localMachineName (IP: $localIp)"
Write-Host "-----------------------------------------------------------------"

# Ciclo principale continuo
while ($true) {
    $currentIterationTimestamp = Get-Date -Format 'HH:mm:ss'
    # File di log giornaliero
    $data = Get-Date -Format "dd-MM-yyyy"
    $logFile = "$folderPath\log_$sanitizedName_$data.txt"

    # === LOGICA PROCESSO ===
    if ($InputParam -like "*.exe") {
        LogToConsole "`n`n$currentIterationTimestamp [+] Controllo auditing per il processo: $InputParam"

        $procName = $InputParam -replace ".exe", ""
        $processiAttivi = Get-Process | Where-Object {
            ($_.Name -ieq $procName -or $_.Path -like "*\$InputParam") -and (-not $_.HasExited)
        } -ErrorAction SilentlyContinue

        $currentActiveInstanceIdentities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if ($processiAttivi) {
            foreach ($p_active in $processiAttivi) {
                try {
                    if ($p_active.HasExited) { continue }
                    $startTime = $p_active.StartTime
                    $instanceIdentity = "$($p_active.Name)_$($p_active.Id)_$($startTime.ToUniversalTime().Ticks)"
                    $currentActiveInstanceIdentities.Add($instanceIdentity) | Out-Null
                }
                catch [System.InvalidOperationException] {}
                catch {}
            }
        }

        [void]$loggedProcessInstances.RemoveWhere([System.Predicate[string]]{
            param($loggedId) -not $currentActiveInstanceIdentities.Contains($loggedId)
        })

        if ($processiAttivi) {
            foreach ($proc in $processiAttivi) {
                try {
                    if ($proc.HasExited) { continue }

                    $processStartTime = $null
                    try {
                        $processStartTime = $proc.StartTime
                    } catch [System.InvalidOperationException] {
                        LogToConsole "AVVISO: $currentIterationTimestamp - Impossibile ottenere StartTime (processo terminato?) per $($proc.Name) (PID: $($proc.Id)). L'istanza non verrà tracciata."
                        continue 
                    } catch [System.NotSupportedException] {
                         LogToConsole "AVVISO: $currentIterationTimestamp - Impossibile ottenere StartTime (processo inattivo/protetto?) per $($proc.Name) (PID: $($proc.Id)). L'istanza non verrà tracciata."
                        continue
                    } catch { 
                        LogToConsole "AVVISO: $currentIterationTimestamp - Eccezione generica ottenendo StartTime per $($proc.Name) (PID: $($proc.Id)): $($_.Exception.Message). L'istanza non verrà tracciata."
                        continue
                    }
                    
                    $processInstanceIdentity = "$($proc.Name)_$($proc.Id)_$($processStartTime.ToUniversalTime().Ticks)"

                    if (-not $loggedProcessInstances.Contains($processInstanceIdentity)) {
                        $ownerInfoResult = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue | ForEach-Object { $_.GetOwner() }
                        
                        $username = "N/D (proprietario non determinabile)" 
                        if ($ownerInfoResult) {
                            if ($ownerInfoResult.ReturnValue -eq 0) {
                                $username = if ($ownerInfoResult.User) { $ownerInfoResult.User } else { "N/D" }
                            } else {
                                $username = "N/D (err GWMI: $($ownerInfoResult.ReturnValue))"
                            }
                        }

                        $detectionTimestamp = Get-Date
                        $msg = "$($detectionTimestamp.ToString('dd-MM-yyyy HH:mm:ss')) - Macchina: $localMachineName (IP: $localIp) - PID: $($proc.Id) - Nome: $($proc.Name) avviato da $username"

                        $logExistsInDailyFile = $false
                        if (Test-Path $logFile) {
                            if (Select-String -Path $logFile -Pattern ([regex]::Escape($msg)) -Quiet) {
                                $logExistsInDailyFile = $true
                            }
                        }
                        if (-not $logExistsInDailyFile) {
                            LogToFile $msg $logFile
                            LogToConsole $msg
                        }

                        $logExistsInCumulativeFile = $false
                        if (Test-Path $cumulativeLogFile) {
                            if (Select-String -Path $cumulativeLogFile -Pattern ([regex]::Escape($msg)) -Quiet) {
                                $logExistsInCumulativeFile = $true
                            }
                        }
                        if (-not $logExistsInCumulativeFile) {
                            LogToFile $msg $cumulativeLogFile
                            if ($logExistsInDailyFile -and !$logExistsInCumulativeFile) {
                                LogToConsole "(Aggiunto al log cumulativo) $msg"
                            }
                        }
                        
                        $loggedProcessInstances.Add($processInstanceIdentity) | Out-Null
                    }
                }
                catch { 
                    LogToConsole "⚠️ $currentIterationTimestamp Errore DURANTE ELABORAZIONE PROCESSO $($proc.Name) (PID: $($proc.Id)): $($_.Exception.Message)"
                }
            }
        } else {
            LogToConsole "$currentIterationTimestamp ℹ️ Il processo $InputParam non è attualmente in esecuzione (o nessun processo corrispondente trovato)."
        }

    # === LOGICA UTENTE ===
    } else {
        LogToConsole "`n`n$currentIterationTimestamp [+] Controllo auditing per l'utente: $InputParam (eventi da $($lastUserEventCheckTime.ToString('HH:mm:ss')))"
        
        $queryStartTimeForUserEvents = $lastUserEventCheckTime 
        $eventi = $null # Inizializza eventi a null
        $currentQueryEndTime = Get-Date # Orario di default se la query fallisce o non produce eventi

        try {
            $eventi = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=$queryStartTimeForUserEvents} -ErrorAction Stop
            $currentQueryEndTime = Get-Date # Registra l'ora subito dopo la query

            if ($eventi) {
                foreach ($evento in $eventi) {
                    # Assicurati che l'evento sia effettivamente NUOVO rispetto a $queryStartTimeForUserEvents.
                    # Get-WinEvent con StartTime è inclusivo (>=), quindi un evento esattamente a $queryStartTimeForUserEvents verrebbe preso.
                    # Per evitare di riprocessare l'ultimo evento del ciclo precedente se $lastUserEventCheckTime era l'ora di quell'evento,
                    # si potrebbe aggiungere un millisecondo a $queryStartTimeForUserEvents o filtrare qui.
                    # Tuttavia, la logica di Select-String per duplicati dovrebbe gestire questo.

                    $exePath = $evento.Properties[5].Value
                    $targetUserSid = $evento.Properties[0].Value
                    $userAccount = $targetUserSid 
                    try {
                        $account = New-Object System.Security.Principal.SecurityIdentifier($targetUserSid)
                        $userAccount = $account.Translate([System.Security.Principal.NTAccount]).Value
                        if ($userAccount -match '\\') {
                           $userAccount = ($userAccount -split '\\')[1]
                        }
                    } catch {}

                    $time = $evento.TimeCreated
                    $msg = "$($time.ToString('dd-MM-yyyy HH:mm:ss')) - Utente: $userAccount (su Macchina: $localMachineName IP: $localIp) ha avviato '$exePath' (ID Evento Log: $($evento.RecordId))"

                    if ($userAccount -like "*$InputParam*" -or $InputParam -like "*$userAccount*") {
                        $logExistsInDailyFile = $false
                        if (Test-Path $logFile) {
                            if (Select-String -Path $logFile -Pattern ([regex]::Escape($msg)) -Quiet) {
                                $logExistsInDailyFile = $true
                            }
                        }
                        if (-not $logExistsInDailyFile) {
                            LogToFile $msg $logFile
                            LogToConsole $msg
                        }

                        $logExistsInCumulativeFile = $false
                        if (Test-Path $cumulativeLogFile) {
                            if (Select-String -Path $cumulativeLogFile -Pattern ([regex]::Escape($msg)) -Quiet) {
                                $logExistsInCumulativeFile = $true
                            }
                        }
                        if (-not $logExistsInCumulativeFile) {
                            LogToFile $msg $cumulativeLogFile
                            if ($logExistsInDailyFile -and !$logExistsInCumulativeFile) {
                                LogToConsole "(Aggiunto al log cumulativo) $msg"
                            }
                        }
                    }
                }
            } else {
                 LogToConsole "$currentIterationTimestamp ℹ️ Nessun nuovo evento di avvio processo (ID 4688) trovato per i criteri utente da $($queryStartTimeForUserEvents.ToString('HH:mm:ss'))."
            }
        }
        catch {
            LogToConsole "⚠️ $currentIterationTimestamp Errore durante il recupero degli eventi di sicurezza: $($_.Exception.Message)"
            $currentQueryEndTime = Get-Date # Aggiorna anche in caso di errore per non bloccare $lastUserEventCheckTime
        }
        finally {
            # Aggiorna l'ora dell'ultimo controllo per la prossima iterazione, basandosi su quando questa query è terminata
            $lastUserEventCheckTime = $currentQueryEndTime
        }
    }

    LogToConsole "`n$currentIterationTimestamp 📁 Log giornaliero ($data): $logFile"
    LogToConsole "$currentIterationTimestamp 📁 Log cumulativo: $cumulativeLogFile"
    LogToConsole "-----------------------------------------------------------------"

    Start-Sleep -Seconds 2
}