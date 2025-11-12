# RunInSession
This is a tool that can be used to run a process in a user session other than its own running context.
The program acheives this by registering a task for SYSTEM to re-run this process with the same flags inorder to gain the privliges needed to duplicate a users token and call CreateProcessAsUserA

## Usage
An administrator account or one with permissions to schedule tasks as SYSTEM is required to run this

### Flags
-a               Run in all sessions
-id <sessionID>  Specify a Session ID to run in
-path <path>     (Required) Specify the path to the executable

### Example
<pre>
./RunInSession -id 3 -path "C:\Windows\notepad.exe"
</pre>