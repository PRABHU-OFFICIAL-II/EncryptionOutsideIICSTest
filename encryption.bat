@echo off
REM Set the directory to where the Java files are located
setlocal
set JAVA_DIR=%~dp0

REM Run the Java program
echo Running SimpleEncryptionUtil...
java SimpleEncryptionUtil

endlocal
