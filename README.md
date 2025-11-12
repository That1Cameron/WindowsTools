# A set of windows tools to help administer and manipulate the system

The purpose of this repo is to contain binary and ps options for various Windows utilities I build while learning more about different parts of the Windows OS and how to manipulate it.
The powershell script and binaries are designed to behave the same to prevent users from needing to know different arguments for each.

## Structure
<pre>
├── README.md   # Main documentation file
│
├── RunInSession/   # Tool for executing commands within a logged-in session
│ ├── bin/   # Binary version source code
│ ├── ps script/   # PowerShell script version
│ └── README.md   # Tool-specific documentation
│
├── ModifyRID/   # Utility for modifying RID values of objects
│ ├── bin/   # Binary version source code
│ ├── ps script/   # PowerShell script version
│ └── README.md   # Tool-specific documentation
│
└── ... # future tools follow the same structure
</pre>


## Tools

### RunInSession
This tool can be used to run a process in any or all active sessions on the host machine. This will need administrator permissions to run properly.
