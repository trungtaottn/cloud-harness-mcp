#!/usr/bin/env bash
# kill-session — guest-side process-group terminator for exec.killSession.
# Reads newline-separated pids from a pid file (each pid is a process-group
# leader recorded by the worker runners) and signals each group in reverse
# order: TERM, bounded wait, KILL, bounded wait. Mirrors the docker
# backend's terminateContainerProcessGroup ladder so exec.killSession has
# identical semantics on both backends. Exits 0 once every group is gone.
set -u

pid_file="${1:-}"
if [[ -z "$pid_file" ]]; then
  echo "usage: kill-session <pid-file>" >&2
  exit 2
fi

for _ in {1..20}; do
  if [[ -r "$pid_file" ]]; then
    mapfile -t pids < "$pid_file"
    for ((i = ${#pids[@]} - 1; i >= 0; i--)); do
      if [[ "${pids[$i]}" =~ ^[0-9]+$ ]]; then
        kill -TERM -- "-${pids[$i]}" 2>/dev/null || true
      fi
    done
    for _ in {1..20}; do
      alive=0
      for pid in "${pids[@]}"; do
        if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 -- "-$pid" 2>/dev/null; then
          alive=1
        fi
      done
      if ((alive == 0)); then
        rm -f -- "$pid_file"
        exit 0
      fi
      sleep 0.05
    done
    for pid in "${pids[@]}"; do
      if [[ "$pid" =~ ^[0-9]+$ ]]; then
        kill -KILL -- "-$pid" 2>/dev/null || true
      fi
    done
    for _ in {1..20}; do
      alive=0
      for pid in "${pids[@]}"; do
        if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 -- "-$pid" 2>/dev/null; then
          alive=1
        fi
      done
      if ((alive == 0)); then
        rm -f -- "$pid_file"
        exit 0
      fi
      sleep 0.05
    done
    exit 1
  fi
  sleep 0.025
done
exit 1
