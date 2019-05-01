@echo off
@title Login Server
set CLASSPATH=.;dist\*
java -Xmx100m gundam.sniffer.Driver
pause
