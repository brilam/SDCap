@echo off
@title Gundam Sniffer
set CLASSPATH=.;dist\*
java -Xmx100m gundam.sniffer.Driver
pause
