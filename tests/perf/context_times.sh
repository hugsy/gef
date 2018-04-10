#!/bin/bash

# Bail out early on an unexpected error
set -e

time_gef_context() {
    # Run twice to minimize jitter
    gdb -ex 'start' -ex 'ni' -ex 'pi import profile' -ex "pi profile.run(\"gdb.execute('context')\", sort=\"cumtime\")" -ex 'quit' ../binaries/pattern.out >/dev/null 2>&1
    gdb -ex 'start' -ex 'ni' -ex 'pi import profile' -ex "pi profile.run(\"gdb.execute('context')\", sort=\"cumtime\")" -ex 'quit' ../binaries/pattern.out 2>&1 | get_context_time
}

get_context_time() {
    grep "gdb.execute('context')" | tr -s ' ' | cut -d ' ' -f 5
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
