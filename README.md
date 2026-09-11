# test
!TESTING!

1. cc -Wall -Wextra -O2 -c parser.c -o parser.o
2. cc -Wall -Wextra -O2 parser.c syssec.c -o syssec
3. ./syssec , for verbose: ./syssec -v, to save report: ./syssec -o FILE
4. example execution: ./syssec -v -o report.html
5. for unaccessed sections of the report parsing, use elevated user, i.e. root: doas ./syssec -v -o report.html
6. to configure doas, write "permit persist :wheel" OR for a specific user "permit persist john" in the conf file located in /usr/local/etc/doas.conf
