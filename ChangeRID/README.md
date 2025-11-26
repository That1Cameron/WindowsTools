# ChangeRID WIP
This is a tool that can be used to change a user's RID to that of 500 (administrator)
Windows RIDs are a component of their SID that behave similarly to linux UIDs

## Usage
An administrator account or one with permissions to schedule tasks as SYSTEM is required to run this

### Flags
-h               help
-r <target rid>  the rid of the user you want to change
-n <name>        The name associated with the user you want to change

### Example
<pre>
./ChangeRID -r 1001
</pre>