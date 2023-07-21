# Magix

Command line interface (CLI) binaries for non-kosher shenanigans.

## Magix Hide

Create a child process that doesn't hang the terminal running your script.

> YEET that process out of here!

### Usage

The binary support some configuration options.

* --help
** Print all options and their description
* --wait
** Wait for the child process to exit before continuing => --wait
** Wait for the child process to exit, or timeout after 5000 milliseconds => --wait=5000
* --stdin/--stdout/--stderr
** Bind respective input/output (IO) streams to a file => --stdin=<path-to-file>
** Bind output stream to another => --stdout=<path-to-logfile> --stderr=stdout


### Run notepad as detached child process

```powershell
yeet.exe "$($env:SystemRoot)\notepad.exe" "$($env:UserProfile)\Desktop\new-document.txt"
```

### Run CMD as detached child process while collecting console output

```powershell
yeet.exe --stdout=./output.log --stderr=stdout -- "$($env:ComSpec)" "/C ECHO Hello from CMD!"
```

### Display windows version waiting 10 seconds for the process to close

```powershell
yeet.exe --wait=10000 -- "$([Environment]::GetFolderPath("SYSTEM"))\winver.exe"
```

## Magix Sneak

Run a child process with permissions of another user.

> UPCOMING

## Magix Tada

Run a child process inside another session on the local computer.

> UPCOMING