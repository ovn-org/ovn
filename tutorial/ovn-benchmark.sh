#!/bin/bash

DEFAULT_NODES=200

PROCESS_NAME=()
FILE_NAME=""
NODES=""
PROCESS_PIDS=()
FINAL_PEAK_KB=()
DEBUG=false
BATCH_SIZE=""
VALGRIND_MODE=false
VALGRIND_PIDS=()
MASSIF_FILES=()
BENCHMARK_TMPDIR=""

on_interrupt() {
    echo ""
    if [ "$VALGRIND_MODE" = true ]; then
        echo "Exiting benchmark. Restarting tracked sandbox processes..."
    fi
    exit 1
}
trap on_interrupt INT

kill_insist() {
    local pid=$1
    local timeout_ms=${2:-30000}

    env kill -0 "$pid" 2> /dev/null && \
        env kill --timeout "$timeout_ms" KILL "$pid"
}

# In valgrind mode, the original daemons are killed and replaced with
# valgrind-wrapped copies.  This cleanup ensures they are restored on
# both normal exit and Ctrl+C so the sandbox is not left broken.
cleanup() {
    # Stop any valgrind processes still running.
    for vpid in "${VALGRIND_PIDS[@]}"; do
        kill_insist $vpid
    done

    if [ -n "$BENCHMARK_TMPDIR" ]; then
        # Restart each daemon from the cmdline/cwd saved before we
        # killed it, but only if it is not already running.
        for i in "${!PROCESS_NAME[@]}"; do
            pn="${PROCESS_NAME[$i]}"
            if [ -f "$BENCHMARK_TMPDIR/cmdline.$pn" ] \
               && ! pgrep -x "$pn" >/dev/null 2>&1; then
                restart_cwd=$(cat "$BENCHMARK_TMPDIR/cwd.$pn")
                mapfile -d '' restart_args < "$BENCHMARK_TMPDIR/cmdline.$pn"
                # Drop trailing empty element from /proc/*/cmdline's final NUL.
                if [ ${#restart_args[@]} -gt 0 ] \
                   && [ -z "${restart_args[-1]}" ]; then
                    unset 'restart_args[-1]'
                fi
                (cd "$restart_cwd" && "${restart_args[@]}" >/dev/null 2>&1)
            fi
        done

        rm -rf "$BENCHMARK_TMPDIR"
    fi
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help|--usage)
            echo "Usage: $0 [OPTIONS] [NODES] [PROCESS...]"
            echo ""
            echo "Arguments:"
            echo "  NODES         Number of nodes to create" \
                 "(default: $DEFAULT_NODES)"
            echo "  PROCESS       Process(es) to track:" \
                 "ovn-northd, ovn-controller"
            echo "                (default: both)"
            echo ""
            echo "Options:"
            echo "  -f, --file FILE    Load NB database from file"
            echo "  -b, --batch-size N Nodes per chassis" \
                 "(default: NODES/10)"
            echo "  -v, --valgrind     Track heap with Valgrind" \
                 "Massif (slower, accurate)"
            echo "  -d, --debug           Enable debug output"
            echo "  -h, --help            Show this help message"
            echo ""
            echo "Memory tracking:"
            echo "  Default: peak virtual memory (VmPeak) from"
            echo "  /proc/<pid>/status."
            echo "  --valgrind: peak heap via Valgrind Massif."
            echo "  Expect 10-50x slowdown; 500 nodes or fewer"
            echo "  recommended."
            echo ""
            echo "Examples:"
            echo "  $0                      # 200 nodes, track both processes"
            echo "  $0 50                   # 50 nodes"
            echo "  $0 50 ovn-northd        # 50 nodes, track only ovn-northd"
            echo "  $0 --valgrind           # Use Valgrind Massif, not VmPeak"
            echo "  $0 --file ovnnb_db.db   # Load from file"
            echo "  $0 --debug 20           # 20 nodes with debug output"
            echo "  $0 50 -b 10             # 50 nodes, 10 per chassis"
            echo ""
            echo "Note: if only tracking one process, # of nodes is required"
            exit 0
            ;;
        -b|--batch-size)
            if [ -z "$2" ]; then
                echo "Error: $1 requires an argument"
                exit 1
            fi
            BATCH_SIZE="$2"
            shift 2
            ;;
        -v|--valgrind)
            VALGRIND_MODE=true
            shift
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -f|--file)
            if [ -z "$2" ]; then
                echo "Error: $1 requires an argument"
                exit 1
            fi
            FILE_NAME="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            if [ -z "$NODES" ]; then
                NODES="$1"
            else
                # Normalize process names: accept both "northd" and
                # "ovn-northd".
                case "$1" in
                    northd)
                        PROCESS_NAME+=("ovn-northd")
                        ;;
                    controller)
                        PROCESS_NAME+=("ovn-controller")
                        ;;
                    *)
                        PROCESS_NAME+=("$1")
                        ;;
                esac
            fi
            shift
            ;;
    esac
done

# Must be run from inside the sandbox (tutorial/sandbox/).
if [ ! -d "$PWD/sandbox" ]; then
    echo "Error: must be run from inside the OVN sandbox."
    echo "Start one with: make sandbox"
    exit 1
fi

# Apply defaults if not set by user.
NODES=${NODES:-$DEFAULT_NODES}

if [ -z "$BATCH_SIZE" ]; then
    BATCH_SIZE=$((NODES / 10))
fi
if [ "$BATCH_SIZE" -lt 1 ]; then
    BATCH_SIZE=1
fi

# Track both processes if not specified.
if [ ${#PROCESS_NAME[@]} -eq 0 ]; then
    PROCESS_NAME=("ovn-controller" "ovn-northd")
fi

if [ "$DEBUG" = true ]; then
    echo "Nodes:       $NODES"
    echo "Batch size:  $BATCH_SIZE"
    echo "Processes:   ${PROCESS_NAME[*]}"
    echo "File:        ${FILE_NAME:-None}"
fi

PID_ERRORS=false
for pn in "${PROCESS_NAME[@]}"; do
    all_pids=$(pgrep -x "$pn")
    if [ -z "$all_pids" ]; then
        echo "Error: Could not find process matching '$pn'"
        PID_ERRORS=true
        continue
    fi

    if [ "$(echo "$all_pids" | wc -l)" -gt 1 ]; then
        echo "Error: Multiple $pn processes found" \
             "(PIDs: $(echo $all_pids | tr '\n' ' '))"
        PID_ERRORS=true
        continue
    fi

    PROCESS_PIDS+=("$all_pids")
done

if [ "$PID_ERRORS" = true ]; then
    echo "Kill stale processes or ensure only one sandbox is running."
    exit 1
fi

if [ "$DEBUG" = true ]; then
    for i in "${!PROCESS_NAME[@]}"; do
        echo "Tracking memory for ${PROCESS_NAME[$i]}" \
             "(PID: ${PROCESS_PIDS[$i]})"
    done
fi

if [ "$VALGRIND_MODE" = true ]; then
    if ! command -v valgrind >/dev/null 2>&1; then
        echo "Error: valgrind is not installed or not in PATH"
        exit 1
    fi

    if [ "$NODES" -gt 500 ]; then
        echo "Warning: valgrind mode with $NODES nodes may be very slow." \
             "Consider using 500 or fewer nodes for heap profiling."
    fi

    BENCHMARK_TMPDIR=$(mktemp -d)
    echo "Restarting processes under Valgrind Massif..."
    echo "(Expect 10-50x slowdown)"

    for i in "${!PROCESS_NAME[@]}"; do
        pn="${PROCESS_NAME[$i]}"
        pid="${PROCESS_PIDS[$i]}"

        # Read the original command line so we can restart the daemon later.
        # /proc/<pid>/cmdline is NUL-separated; the trailing NUL produces an
        # empty final element which must be dropped.
        mapfile -d '' orig_args < /proc/$pid/cmdline
        if [ ${#orig_args[@]} -gt 0 ] \
           && [ -z "${orig_args[-1]}" ]; then
            unset 'orig_args[-1]'
        fi

        proc_cwd=$(readlink /proc/$pid/cwd)
        massif_file="$BENCHMARK_TMPDIR/massif.$pn.out"
        MASSIF_FILES+=("$massif_file")

        # Save original cmdline and cwd so we can restart after valgrind.
        cp /proc/$pid/cmdline "$BENCHMARK_TMPDIR/cmdline.$pn"
        echo "$proc_cwd" > "$BENCHMARK_TMPDIR/cwd.$pn"

        # Valgrind runs the process in the foreground, so strip args
        # that assume daemonized execution:
        #   --detach    : can't daemonize under valgrind
        #   --no-chdir  : only meaningful with --detach
        #   --pidfile   : valgrind doesn't write one (OVS uses
        #                 optional_argument so bare --pidfile never
        #                 takes a separate arg; only --pidfile=FILE)
        #   --monitor   : would fork a monitor child under valgrind,
        #                 causing two processes to race on massif output
        filtered_args=()
        for arg in "${orig_args[@]}"; do
            case "$arg" in
                --detach|--no-chdir|--monitor) ;;
                --pidfile|--pid-file) ;;
                --pidfile=*|--pid-file=*) ;;
                *) filtered_args+=("$arg") ;;
            esac
        done

        if [ "$DEBUG" = true ]; then
            echo "Stopping $pn (PID $pid)..."
        fi

        kill_insist $pid

        if [ "$DEBUG" = true ]; then
            echo "Starting $pn under valgrind:"
            echo "  valgrind --tool=massif --massif-out-file=$massif_file" \
                 "${filtered_args[*]}"
        fi

        # exec replaces the subshell with valgrind so $! is valgrind's
        # actual PID and SIGTERM reaches it to finalize massif output.
        # --max-snapshots, --detailed-freq, and --depth reduce the cost
        # of each snapshot, which otherwise scales with the number of
        # live allocations and becomes prohibitive at large node counts.
        (cd "$proc_cwd" && exec valgrind \
            --tool=massif \
            --massif-out-file="$massif_file" \
            --max-snapshots=50 \
            --detailed-freq=20 \
            --depth=10 \
            "${filtered_args[@]}" \
            >/dev/null 2>&1) &
        VALGRIND_PIDS+=("$!")
    done

    # Poll until northd and controller are processing.
    # --wait=hv confirms the full stack is functional.
    # (NB -> northd -> SB -> controller).
    echo "Waiting for processes to reconnect..."
    deadline=$(($(date +%s) + 60))
    while ! ovn-nbctl --timeout=5 --wait=hv sync 2>/dev/null; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "Warning: processes did not reconnect within 60 seconds"
            break
        fi
        sleep 1
    done
fi

if [ "$DEBUG" = true ]; then
    DEBUG_FLAG="-d"
else
    DEBUG_FLAG=""
fi

REMOTE="unix:$PWD/sandbox/nb1.ovsdb"
PY_ARGS="-n $NODES -b $BATCH_SIZE -r $REMOTE $DEBUG_FLAG"

do_sync() {
    if ! ovn-nbctl --timeout=120 --wait=hv sync; then
        echo "Warning: ovn-nbctl sync timed out; results may be incomplete."
    fi
}

run_phase() {
    if ! python3 ovn-benchmark.py "$1" $PY_ARGS; then
        echo "Error: phase '$1' failed"
        return 1
    fi
}

# %s%2N gives epoch seconds with two fractional digits (hundredths).
PY_START=$(date +%s%2N)

# Load database from file or generate with Python script.
if [ -n "$FILE_NAME" ]; then
    echo "Loading database from file: $FILE_NAME"
    if [ ! -f "$FILE_NAME" ]; then
        echo "Error: File '$FILE_NAME' not found"
        exit 1
    fi
    if [ "$VALGRIND_MODE" != true ]; then
        echo "Warning: -f mode uses VmPeak, which is a lifetime" \
             "high-water mark."
        echo "Restart the sandbox before each run for accurate readings."
    fi
    ovsdb-client restore "$REMOTE" < "$FILE_NAME"
else
    echo "Generating database with Python script"
    run_phase create || exit 1
fi

BIND_COUNT=$((BATCH_SIZE < NODES ? BATCH_SIZE : NODES))
for i in $(seq 0 $((BIND_COUNT - 1))); do
    ovs-vsctl add-port br-int lsp-${i}-0 -- \
        set interface lsp-${i}-0 \
        external_ids:iface-id=lsp-${i}-0
done

do_sync

# Incremental operations: modify and delete a subset of the topology,
# syncing after each group to measure incremental processing time.
# After each sync, check whether northd or lflow triggered a full
# recompute -- an unexpected recompute signals a regression in the
# incremental engine.
INCR_PHASES=(
    add-lsps add-nat add-routes add-policies
    modify-lsps modify-acls modify-nat modify-routes
    modify-lbs modify-addr-sets modify-pg modify-port-sec
    modify-dhcp modify-dns
    delete-lsps delete-nat delete-routes delete-lbs
    delete-acls delete-policies delete-qos
)
declare -A PHASE_ELAPSED
declare -A PHASE_RECOMPUTE

# Phases that use NULL handlers and always trigger a full recompute.
# Recomputes for these are expected, not regressions.
EXPECT_RECOMPUTE="add-routes add-policies modify-routes"
EXPECT_RECOMPUTE="$EXPECT_RECOMPUTE modify-dhcp modify-dns"
EXPECT_RECOMPUTE="$EXPECT_RECOMPUTE delete-routes delete-lbs"
EXPECT_RECOMPUTE="$EXPECT_RECOMPUTE delete-policies delete-qos"

NORTHD_CTL=$(echo "$PWD"/sandbox/ovn-northd.*.ctl)
if [ ! -S "$NORTHD_CTL" ]; then
    echo "Warning: ovn-northd control socket not found;" \
         "engine stats will be unavailable."
    NORTHD_CTL=""
elif [ "$DEBUG" = true ]; then
    echo "northd control socket: $NORTHD_CTL"
fi

check_recompute() {
    local phase="$1" northd_rc lflow_rc result=""
    if [ -z "$NORTHD_CTL" ]; then
        PHASE_RECOMPUTE[$phase]="?"
        return
    fi
    northd_rc=$(ovs-appctl -t "$NORTHD_CTL" \
        inc-engine/show-stats northd recompute 2>/dev/null) || northd_rc=""
    lflow_rc=$(ovs-appctl -t "$NORTHD_CTL" \
        inc-engine/show-stats lflow recompute 2>/dev/null) || lflow_rc=""
    if [ -z "$northd_rc" ] || [ -z "$lflow_rc" ]; then
        PHASE_RECOMPUTE[$phase]="?"
        return
    fi
    if [ "$northd_rc" != "0" ] || [ "$lflow_rc" != "0" ]; then
        if echo "$EXPECT_RECOMPUTE" | grep -qw "$phase"; then
            PHASE_RECOMPUTE[$phase]="OK (recompute, expected)"
        else
            result=""
            if [ "$northd_rc" != "0" ]; then
                result="northd recomputed ($northd_rc)"
            fi
            if [ "$lflow_rc" != "0" ]; then
                [ -n "$result" ] && result="$result, "
                result="${result}lflow recomputed ($lflow_rc)"
            fi
            PHASE_RECOMPUTE[$phase]="WARNING: $result"
        fi
    else
        PHASE_RECOMPUTE[$phase]="OK"
    fi
}

[ -n "$NORTHD_CTL" ] && ovs-appctl -t "$NORTHD_CTL" \
    inc-engine/clear-stats 2>/dev/null
for phase in "${INCR_PHASES[@]}"; do
    PHASE_START=$(date +%s%2N)
    if ! run_phase "$phase"; then
        PHASE_RECOMPUTE[$phase]="FAILED"
        PHASE_END=$(date +%s%2N)
        PHASE_ELAPSED[$phase]=$((PHASE_END - PHASE_START))
        continue
    fi
    do_sync
    check_recompute "$phase"
    [ -n "$NORTHD_CTL" ] && ovs-appctl -t "$NORTHD_CTL" \
        inc-engine/clear-stats 2>/dev/null
    PHASE_END=$(date +%s%2N)
    PHASE_ELAPSED[$phase]=$((PHASE_END - PHASE_START))
done
INCR_END=$(date +%s%2N)

# Compact before measuring memory.
ovs-appctl -t "$PWD/sandbox/nb1" ovsdb-server/compact
ovs-appctl -t "$PWD/sandbox/sb1" ovsdb-server/compact

TOTAL_ELAPSED=$((INCR_END - PY_START))

if [ "$VALGRIND_MODE" = true ]; then
    if [ "$DEBUG" = true ]; then
        echo "Benchmark complete. Stopping valgrind and collecting results..."
    fi

    # Signal all valgrind processes to stop.  Each valgrind instance
    # propagates the signal to its child OVN process, waits for it to
    # exit, then writes the massif output file and exits itself.
    for i in "${!PROCESS_NAME[@]}"; do
        pn="${PROCESS_NAME[$i]}"
        vpid="${VALGRIND_PIDS[$i]}"
        if [ "$DEBUG" = true ]; then
            echo "Stopping valgrind for $pn (PID $vpid)..."
        fi
        kill "$vpid" 2>/dev/null
    done

    deadline=$(($(date +%s) + 60))
    for i in "${!PROCESS_NAME[@]}"; do
        pn="${PROCESS_NAME[$i]}"
        vpid="${VALGRIND_PIDS[$i]}"
        if [ "$DEBUG" = true ]; then
            echo "Waiting for valgrind to write massif output for $pn..."
        fi
        while [ -e "/proc/$vpid" ]; do
            if [ "$(date +%s)" -ge "$deadline" ]; then
                echo "Warning: valgrind for $pn did not exit"
                break
            fi
            sleep 0.1
        done
        if [ "$DEBUG" = true ]; then
            echo "Massif output for $pn ready."
        fi
    done

    for i in "${!PROCESS_NAME[@]}"; do
        pn="${PROCESS_NAME[$i]}"
        massif_file="${MASSIF_FILES[$i]}"
        if [ "$DEBUG" = true ]; then
            echo "Parsing massif output for $pn..."
        fi
        if [ ! -s "$massif_file" ]; then
            echo "Warning: massif output missing for $pn;" \
                 "did valgrind exit cleanly?"
            FINAL_PEAK_KB[$i]=0
        else
            # Sum heap + allocator overhead per snapshot; report the peak.
            FINAL_PEAK_KB[$i]=$(awk -F= '
                /^mem_heap_B=/{h=$2}
                /^mem_heap_extra_B=/{e=$2; t=h+e; if(t>peak) peak=t}
                END{print int(peak/1024)}
            ' "$massif_file")
        fi
    done

    # Daemons are restarted by cleanup() on EXIT.
else
    for i in "${!PROCESS_NAME[@]}"; do
        pid=${PROCESS_PIDS[$i]}
        FINAL_PEAK_KB[$i]=$(awk '/^VmPeak:/{print $2}' \
            /proc/$pid/status 2>/dev/null)
        if [ -z "${FINAL_PEAK_KB[$i]}" ]; then
            echo "Warning: ${PROCESS_NAME[$i]} (PID $pid)" \
                 "is no longer running"
            FINAL_PEAK_KB[$i]=0
        fi
    done
fi

fmt_time() {
    printf "%d.%02ds" $(($1 / 100)) $(($1 % 100))
}

echo ""
echo "=== Benchmark Results ==="
printf "Total time:  %d.%02d seconds\n" \
    $((TOTAL_ELAPSED / 100)) $((TOTAL_ELAPSED % 100))
echo ""
echo "Incremental operations:"
for phase in "${INCR_PHASES[@]}"; do
    printf "  %-18s %-10s %s\n" "$phase:" \
        "$(fmt_time ${PHASE_ELAPSED[$phase]})" \
        "${PHASE_RECOMPUTE[$phase]}"
done
echo ""
if [ "$VALGRIND_MODE" = true ]; then
    echo "Peak heap memory (Valgrind Massif):"
else
    echo "Peak virtual memory (VmPeak):"
fi
for i in "${!PROCESS_NAME[@]}"; do
    printf "  %-15s %d.%d MB  (%d KB)\n" \
        "${PROCESS_NAME[$i]}:" \
        "$((FINAL_PEAK_KB[$i] / 1024))" \
        "$((FINAL_PEAK_KB[$i] % 1024 * 10 / 1024))" \
        "${FINAL_PEAK_KB[$i]}"
done
echo "========================="
echo ""
