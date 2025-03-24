#!/bin/bash
rm -rf cppcheck-main
git clone https://github.com/danmar/cppcheck cppcheck-main
cd cppcheck-main
make -j$(nproc) cppcheck
cd ..

python3 remove_external.py ../build/compile_commands.json
cppcheck-main/cppcheck --project=../build/compile_commands.json --platform=unix64 --std=c++17 --enable=warning --inline-suppr --template="{file}:{line}:{id}{inconclusive: INCONCLUSIVE} {message}" -I /usr/include/ --include=macros.h --suppressions-list=suppressions.txt --output-file=errors.txt --checkers-report=checkers_report.txt --check-level=exhaustive -j$(nproc)
