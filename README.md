# Beastinator
> Beastinator, The Modern FreeBSD malware analysis and security audit tool made for your safety!

[![C Build](https://github.com/ffdiracex/Beastinator_syssec/actions/workflows/c.yml/badge.svg)](https://github.com/ffdiracex/Beastinator_syssec/actions/workflows/c.yml)
[![Rust Build](https://github.com/ffdiracex/Beastinator_syssec/actions/workflows/rust.yml/badge.svg)](https://github.com/ffdiracex/Beastinator_syssec/actions/workflows/rust.yml)
[![License: MIT](https://img.shields.io/badge/License-BSD_3_clause-green)](LICENSE)

!HACKER's NOTE!
1. cc -Wall -Wextra -O2 -c parser.c -o parser.o
2. cc -Wall -Wextra -O2 parser.c syssec.c -o syssec
3. ./syssec , for verbose: ./syssec -v, to save report: ./syssec -o FILE
4. example execution: ./syssec -v -o report.html
5. for unaccessed sections of the report parsing, use elevated user, i.e. root: doas ./syssec -v -o report.html
6. to configure doas, write "permit persist :wheel" OR for a specific user "permit persist john" in the conf file located in /usr/local/etc/doas.conf
