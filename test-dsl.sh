#!/bin/bash

# Find all *.pp files and run puppet noop on them
find test -name '*.pp' | sort | xargs puppet --modulepath=. --noop $@
