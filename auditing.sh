#!/bin/bash

# === Verifica parametro ===
if [ -z "$1" ]; then
  echo "Usa: $0 <nome_process> oppure <nome_utente>"
  exit 1
fi

input="$1"
sanitizedName="${input%.exe}"
folderPath="$HOME/auditing_$sanitizedName"
cumulativeFolderPath="$folderPath/Tutti_i_processi"
data=$(date '+%d-%m-%Y')
logFile="$folderPath/log_${sanitizedName}_${data}.txt"
cumulativeLogFile="$cumulativeFolderPath/processi_completi.txt"

machine_hostname=$(hostname)
machine_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$machine_ip" ]; then
  machine_ip="N/A"
fi

mkdir -p "$cumulativeFolderPath"

log_to_file() {
  echo "$1" >> "$2"
}

log_to_console() {
  echo "$1"
}

cleanup() {
    log_to_console "Script di auditing interrotto per '$input' su $machine_hostname."
    exit 0
}

trap cleanup SIGINT SIGTERM

declare -A pids_logged_this_session

monitoring_started_message_shown=false
last_known_state_valid=true
user_initial_scan_done=false

log_to_console "[+] Avvio monitoraggio continuo per: '$input' su $machine_hostname (IP: $machine_ip)"
log_to_console "    Log giornaliero: $logFile"
log_to_console "    Log cumulativo: $cumulativeLogFile"

# === CICLO DI MONITORAGGIO CONTINUO ===
while true; do
  current_pids_for_process_check=$(pgrep -x "$sanitizedName")

  # === SE È UN PROCESSO (.exe o nome processo trovato da pgrep) ===
  if [[ "$input" == *.exe || -n "$current_pids_for_process_check" ]]; then
    user_initial_scan_done=false 
    if ! $monitoring_started_message_shown || ! $last_known_state_valid; then
        log_to_console "-----------------------------------------------------"
        log_to_console "[+] Rilevato come PROCESSO: $sanitizedName (input: $input)"
        monitoring_started_message_shown=true
        last_known_state_valid=true
    fi

    if [ -n "$current_pids_for_process_check" ]; then
      for pid_proc in $current_pids_for_process_check; do
        if [[ -z "${pids_logged_this_session[$pid_proc]}" ]]; then
          username=$(ps -o user= -p "$pid_proc" --no-headers)
          msg="$(date '+%d-%m-%Y %H:%M:%S') - Host: $machine_hostname - IP: $machine_ip - PID: $pid_proc - Nome: $sanitizedName - Avviato da: $username"
          grep -qxF "$msg" "$logFile" 2>/dev/null || { log_to_console "$msg"; log_to_file "$msg" "$logFile"; }
          grep -qxF "$msg" "$cumulativeLogFile" 2>/dev/null || { log_to_file "$msg" "$cumulativeLogFile"; }
          pids_logged_this_session["$pid_proc"]="LOGGED_AS_PROCESS"
        fi
      done
    else
      if $last_known_state_valid && $monitoring_started_message_shown; then true; fi
    fi

    for logged_pid_val in "${!pids_logged_this_session[@]}"; do
      is_still_running=false
      if [ -n "$current_pids_for_process_check" ]; then
          for current_pid_check_val in $current_pids_for_process_check; do
              if [[ "$logged_pid_val" == "$current_pid_check_val" ]]; then is_still_running=true; break; fi
          done
      fi
      if ! $is_still_running; then unset pids_logged_this_session["$logged_pid_val"]; fi
    done

  # === SE NON È UN PROCESSO, PROVA COME UTENTE ===
  else
    if id "$input" &>/dev/null; then 
      if ! $monitoring_started_message_shown || ! $last_known_state_valid; then
          log_to_console "-----------------------------------------------------"
          log_to_console "[+] Rilevato come UTENTE: $input"
          monitoring_started_message_shown=true; last_known_state_valid=true; user_initial_scan_done=false
      fi

      if ! $user_initial_scan_done; then
          log_to_console "[INFO] Eseguo scansione iniziale dei processi per l'utente '$input'. I processi già attivi non verranno loggati come nuovi."
          initial_user_pids_list=($(ps -u "$input" -o pid= --no-headers))
          for pid_init_val in "${initial_user_pids_list[@]}"; do
              if [ -n "$pid_init_val" ]; then pids_logged_this_session["$pid_init_val"]="INITIAL_SCAN"; fi
          done
          user_initial_scan_done=true
          log_to_console "[INFO] Scansione iniziale per '$input' completata. Monitoraggio dei nuovi processi avviato."
      fi

      processiUtenteConArgs=$(ps -u "$input" -o pid=,args= --no-headers)
      current_user_pids_array=($(ps -u "$input" -o pid= --no-headers))

      script_ps_pattern_args="ps -u $input -o pid=,args= --no-headers"
      script_ps_pattern_pid_only="ps -u $input -o pid= --no-headers"

      if [ -n "$processiUtenteConArgs" ]; then
        while IFS= read -r line; do
          if [ -z "$line" ]; then continue; fi

          current_pid_val="" 
          current_args_val_raw="" 
          read -r current_pid_val current_args_val_raw <<< "$line"
          
          if [ -z "$current_pid_val" ]; then
              continue
          fi
          # if ! [[ "$current_pid_val" =~ ^[0-9]+$ ]]; then continue; fi # Opzionale: controllo PID numerico

          current_args_val_normalized=$(echo "$current_args_val_raw" | xargs)

          is_script_own_command=false
          if [[ "$current_args_val_normalized" == "$script_ps_pattern_args" ]] || \
             [[ "$current_args_val_normalized" == "$script_ps_pattern_pid_only" ]]; then
              is_script_own_command=true
              if [[ -z "${pids_logged_this_session[$current_pid_val]}" ]]; then
                  pids_logged_this_session["$current_pid_val"]="SCRIPT_PS_CMD"
              fi
          fi

          if $is_script_own_command; then
              continue 
          fi
          
          log_command_name_val=""
          if [ -n "$current_args_val_raw" ]; then
              read -r log_command_name_val _ <<< "$current_args_val_raw"
          fi
          if [ -z "$log_command_name_val" ]; then 
              log_command_name_val="<sconosciuto>"
          fi

          if [[ -z "${pids_logged_this_session[$current_pid_val]}" ]]; then
            msg="$(date '+%d-%m-%Y %H:%M:%S') - Host: $machine_hostname - IP: $machine_ip - PID: $current_pid_val - Nome: $log_command_name_val - Avviato da utente: $input"
            
            grep -qxF "$msg" "$logFile" 2>/dev/null || { log_to_console "$msg"; log_to_file "$msg" "$logFile"; }
            grep -qxF "$msg" "$cumulativeLogFile" 2>/dev/null || { log_to_file "$msg" "$cumulativeLogFile"; }
            
            pids_logged_this_session["$current_pid_val"]="LOGGED_NEW_USER_PROC"
          fi
        done <<< "$processiUtenteConArgs"
      fi

      for logged_pid_cleanup_val in "${!pids_logged_this_session[@]}"; do 
        is_still_running_for_user=false
        if [ -z "$logged_pid_cleanup_val" ] || ! [[ "$logged_pid_cleanup_val" =~ ^[0-9]+$ ]] ; then continue; fi

        for current_user_pid_check_val in "${current_user_pids_array[@]}"; do
            if [[ "$logged_pid_cleanup_val" == "$current_user_pid_check_val" ]]; then is_still_running_for_user=true; break; fi
        done
        if ! $is_still_running_for_user; then unset pids_logged_this_session["$logged_pid_cleanup_val"]; fi
      done

    else 
      if $last_known_state_valid; then
          log_to_console "-----------------------------------------------------"
          log_to_console "⚠️ Input '$input' non è (più) un processo attivo né un utente valido. In attesa..."
          last_known_state_valid=false; monitoring_started_message_shown=false; user_initial_scan_done=false
      fi
    fi
  fi

  sleep 2
done
