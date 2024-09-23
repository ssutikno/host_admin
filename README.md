# host_admin
Linux Host Admin ( API ) Include for KVM Server Administration

Execute the executable file on the linux host, and make it run as a service
Call it from browser or use it as API

Hello from your Simple Server Admin API!
This server provides the following functions:

## == System Management ==
- /hwinfo: Get hardware information
- /storage: Get storage usage information
- /memory: Get memory usage information
- /network: Get network interface information
- /processes: Get a list of running processes
- /reboot: Reboot the system
- /shutdown: Shutdown the system
- /user: Change the username and password
  
## == Virtual Machine Management ==
- /vmstatus: Get the status of all VMs
- /vmreset?name=<vm_name>: Reset a VM
- /vmshutdown?name=<vm_name>: Shutdown a VM
- /vminfo?name=<vm_name>: Get information about a VM
  
### Default configuration created.

Username/Password : admin/admin

