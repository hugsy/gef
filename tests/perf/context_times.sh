#!/bin/bash

set -e

time_gef_context() {
    # Run twice to minimize jitter
    gdb -ex 'start' -ex 'ni' -ex 'ni' -ex 'quit' ../binaries/pattern.out >/dev/null 2>&1
    (time gdb -ex 'start' -ex 'ni' -ex 'ni' -ex 'quit' ../binaries/pattern.out 2>&1 >/dev/null) |& get_real_time
}

get_real_time() {
    grep real | tr -s ' ' | cut -f 2 | cut -f 2 -d 'm' | cut -f 1 -d 's'
}

log_this_revision() {
    rev=`git log -1 --pretty="format:%h"`
    printf $rev
    rv=`$1`
    echo ,$rv
}

log_command() {
    log_this_revision "$1" >> stats.csv
}

clear_stats() {
    if [ -e "stats.csv" ]; then
        rm stats.csv
    fi
}

run_on_git_revisions() {
    start_ref=$1
    end_ref=$2
    test_command=$3

    orig_rev=`git rev-list @^..@`
    revs=`git rev-list --reverse ${start_ref}..${end_ref}`

    for rev in $revs; do
        echo "Checking out: $(git log --oneline -1 $rev)"
        git checkout --quiet $rev
	log_command $test_command
        git reset --hard --quiet
    done

    echo "Restoring original commit: $(git log --oneline -1 $orig_rev)"
    git checkout --quiet $orig_rev
}

if [ $# == "2" ]; then
    clear_stats
    run_on_git_revisions $1 $2 "time_gef_context"
fi
