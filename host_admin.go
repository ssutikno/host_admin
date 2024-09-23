package main

import (
	"bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os/exec"
    "os/user"
	"strings"
	"syscall"
	"strconv"
	"io/ioutil"
    "os"
)

type StorageUsage struct {
    Filesystem string `json:"filesystem"`
    Size       string `json:"size"`
    Used       string `json:"used"`
    Avail      string `json:"avail"`
    UsePercent string `json:"use_percent"`
    MountedOn  string `json:"mounted_on"`
}

type MemoryUsage struct {
    Total       string `json:"total"`
    Used        string `json:"used"`
    Free        string `json:"free"`
    Shared      string `json:"shared"`
    BuffCache   string `json:"buff_cache"`
    Available   string `json:"available"`
}

type Process struct {
    PID  int    `json:"pid"`
    Name string `json:"name"`
}

type Config struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type VMStatus struct {
    Name   string `json:"name"`
    Status string `json:"status"`
    // Add more fields as needed based on your VM information
}

type NetworkInterface struct {
    Name       string `json:"name"`
    Status     string `json:"status"`
    IP         string `json:"ip"`
    MACAddress string `json:"mac_address"`
}

const configFile = "config.json"

func main() {
    http.HandleFunc("/", handleRoot)
    http.HandleFunc("/storage", handleStorage)
	http.HandleFunc("/processes", handleProcesses)
	http.HandleFunc("/reboot", basicAuth(handleReboot))
    http.HandleFunc("/shutdown", basicAuth(handleShutdown))
	http.HandleFunc("/changeCredentials", basicAuth(handleChangeCredentials)) 
	http.HandleFunc("/memory", handleMemory)
    http.HandleFunc("/network", handleNetwork)
	http.HandleFunc("/hwinfo", handleHWInfo)
    http.HandleFunc("/user", basicAuth(handleCredentialsForm))

    http.HandleFunc("/vmstatus", handleVMStatus)
    http.HandleFunc("/vmreset", handleVMReset)
    http.HandleFunc("/vmshutdown", handleVMShutdown)
    http.HandleFunc("/vminfo", handleVMInfo)
    fmt.Println("Server listening on port 8080...")
    http.ListenAndServe(":8080", nil)
}

func readConfig() (Config, error) {
    data, err := ioutil.ReadFile(configFile)
    if err != nil {
        return Config{}, err
    }

    var config Config
    err = json.Unmarshal(data, &config)
    return config, err
}

func writeConfig(config Config) error {
    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(configFile, data, 0600) // 0600 for read/write permissions for the owner
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "Hello from your Simple Server Admin API!")
	fmt.Fprintln(w, "This server provides the following functions:")
    fmt.Fprintln(w, "== System Management ==")
    fmt.Fprintln(w, "- /hwinfo: Get hardware information")
    fmt.Fprintln(w, "- /storage: Get storage usage information")
    fmt.Fprintln(w, "- /memory: Get memory usage information")
    fmt.Fprintln(w, "- /network: Get network interface information")
    fmt.Fprintln(w, "- /processes: Get a list of running processes")
    fmt.Fprintln(w, "- /reboot: Reboot the system")
    fmt.Fprintln(w, "- /shutdown: Shutdown the system")
	fmt.Fprintln(w, "- /user: Change the username and password")	
    fmt.Fprintln(w, "== Virtual Machine Management ==")
    fmt.Fprintln(w, "- /vmstatus: Get the status of all VMs")   
    fmt.Fprintln(w, "- /vmreset?name=<vm_name>: Reset a VM")    
    fmt.Fprintln(w, "- /vmshutdown?name=<vm_name>: Shutdown a VM")      
    fmt.Fprintln(w, "- /vminfo?name=<vm_name>: Get information about a VM")
    

	// Check if config file exists

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		// Create default config
		defaultConfig := Config{
			Username: "admin",
			Password: "admin",
		}
		err := writeConfig(defaultConfig)
		if err != nil {
			http.Error(w, "Error creating default configuration", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "Default configuration created.")
		fmt.Fprintln(w, "Username: admin")
		fmt.Fprintln(w, "Password: admin")
	}
}

func handleStorage(w http.ResponseWriter, r *http.Request) {
    usages, err := getStorageUsage()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(usages) 

}

func basicAuth(handler http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
		config, err := readConfig()
        if err != nil {
            http.Error(w, "Error reading configuration", http.StatusInternalServerError)
            return
        }
        user, pass, ok := r.BasicAuth()
        if !ok || user != config.Username || pass != config.Password {
            w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        handler(w, r) 

    }
}
func handleReboot(w http.ResponseWriter, r *http.Request) {
    err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
    if err != nil {
        http.Error(w, "Failed to reboot: "+err.Error(), http.StatusInternalServerError)
        return
    }
    fmt.Fprintln(w, "Reboot initiated")
}

func handleShutdown(w http.ResponseWriter, r *http.Request) {
    cmd := exec.Command("shutdown", "-h", "now")
    err := cmd.Run()
    if err != nil {
        http.Error(w, "Failed to shutdown: "+err.Error(), http.StatusInternalServerError)
        return
    }
    fmt.Fprintln(w, "Shutdown initiated")
}

func handleMemory(w http.ResponseWriter, r *http.Request) {
    usage, err := getMemoryUsage()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json") 

    json.NewEncoder(w).Encode(usage) 

}

func handleNetwork(w http.ResponseWriter, r *http.Request) {
    networkInterfaces, err := getNetworkInterfaces()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(networkInterfaces) 

}

func getNetworkInterfaces() ([]NetworkInterface, error) {
    cmd := exec.Command("ip", "addr")
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        return nil, fmt.Errorf("failed to execute ip addr command: %v", err)
    }

    lines := strings.Split(out.String(), "\n")
    var interfaces []NetworkInterface
    var currentInterface NetworkInterface

    for _, line := range lines {
        line = strings.TrimSpace(line)
        if strings.HasPrefix(line, " ") {
            if strings.HasPrefix(line, "    inet ") {
                parts := strings.Fields(line)
                if len(parts) >= 2 {
                    currentInterface.IP = parts[1]
                }
            } else if strings.HasPrefix(line, "    link/ether ") {
                parts := strings.Fields(line)
                if len(parts) >= 2 {
                    currentInterface.MACAddress = parts[1]
                }
            }
        } else {
            if len(currentInterface.Name) > 0 {
                interfaces = append(interfaces, currentInterface)
            }
            parts := strings.Fields(line)
            if len(parts) >= 2 {
                currentInterface = NetworkInterface{
                    Name:   parts[1],
                    Status: "UP", // Assuming interfaces listed by 'ip addr' are up
                }
            } else {
                currentInterface = NetworkInterface{}
            }
        }
    }

    if len(currentInterface.Name) > 0 {
        interfaces = append(interfaces, currentInterface)
    }

    return interfaces, nil
}

func handleHWInfo(w http.ResponseWriter, r *http.Request) {
    hwInfo, err := getHWInfo()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(hwInfo) 

}

func getHWInfo() (string, error) {
    cmd := exec.Command("lshw", "-json")
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        return "", fmt.Errorf("failed to execute lshw command: %v", err)
    }

    output := out.String()

    // Attempt to parse the output as JSON
    var hwData interface{}
    err = json.Unmarshal([]byte(output), &hwData)
    if err != nil {
        // If parsing fails, try to fix common formatting issues
        output = strings.ReplaceAll(output, ",\n]", "\n]") // Remove trailing comma before closing bracket
        err = json.Unmarshal([]byte(output), &hwData)
        if err != nil {
            return "", fmt.Errorf("failed to parse lshw output as JSON: %v", err)
        }
    }

    // Re-encode the data to ensure consistent JSON formatting
    jsonData, err := json.MarshalIndent(hwData, "", "  ")
    if err != nil {
        return "", fmt.Errorf("failed to re-encode lshw data as JSON: %v", err)
    }

    return string(jsonData), nil
}

func handleProcesses(w http.ResponseWriter, r *http.Request) {
    processes, err := getRunningProcesses()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(processes) 

}


func getStorageUsage() ([]StorageUsage, error) {
    cmd := exec.Command("df", "-h") // Use 'df -h' for human-readable output
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        return nil, fmt.Errorf("failed to execute df command: %v", err)
    }

    lines := strings.Split(out.String(), "\n")
    var usages []StorageUsage
    for _, line := range lines[1:] { // Skip header line
        fields := strings.Fields(line)
        if len(fields) >= 6 {
            usages = append(usages, StorageUsage{
                Filesystem: fields[0],
                Size:       fields[1],
                Used:       fields[2],
                Avail:      fields[3],
                UsePercent: fields[4],
                MountedOn:  fields[5],
            })
        }
    }

    return usages, nil
}

func getMemoryUsage() (MemoryUsage, error) {
    cmd := exec.Command("free", "-h")
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        return MemoryUsage{}, fmt.Errorf("failed to execute free command: %v", err)
    }

    lines := strings.Split(out.String(), "\n")
    fields := strings.Fields(lines[1]) // Get fields from the "Mem:" line
    if len(fields) < 7 {
        return MemoryUsage{}, fmt.Errorf("unexpected output from free command")
    }

    return MemoryUsage{
        Total:     fields[1],
        Used:      fields[2],
        Free:      fields[3],
        Shared:    fields[4],
        BuffCache: fields[5],
        Available: fields[6],
    }, nil
}

func getRunningProcesses() ([]Process, error) {
    currentUser, err := user.Current()
    if err != nil {
        return nil, fmt.Errorf("failed to get current user: %v", err)
    }

    cmd := exec.Command("ps", "-u", currentUser.Username, "-o", "pid,comm")
    var out bytes.Buffer
    cmd.Stdout = &out
    err = cmd.Run()
    if err != nil {
        return nil, fmt.Errorf("failed to list processes: %v", err)
    }

    lines := strings.Split(out.String(), "\n")
    var processes []Process
    for _, line := range lines[1:] { // Skip header line
        fields := strings.Fields(line)
        if len(fields) >= 2 {
            pid, err := strconv.Atoi(fields[0])
            if err != nil {
                continue // Skip lines with invalid PIDs
            }
            processes = append(processes, Process{
                PID:  pid,
                Name: fields[1],
            })
        }
    }

    return processes, nil
}

func handleCredentialsForm(w http.ResponseWriter, r *http.Request) {
    // Simple HTML form
    form := `
<!DOCTYPE html>
<html>
<head>
<title>Change Credentials</title>
</head>
<body>
    <h1>Change Credentials</h1>
    <form action="/changeCredentials" method="post">
        <label for="username">New Username:</label><br>
        <input type="text" id="username" name="username"><br><br>
        <label for="password">New Password:</label><br>
        <input type="password" id="password" name="password"><br><br> 

        <input type="submit" value="Submit">
    </form> 
 
</body>
</html>
`
    fmt.Fprint(w, form)
}

func handleChangeCredentials(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return 

    }

    err := r.ParseForm()
    if err != nil {
        http.Error(w, "Error parsing form", http.StatusBadRequest)
        return 

    }

    newUsername := r.FormValue("username")
    newPassword := r.FormValue("password")

    // ... (Add validation and sanitization here if needed)

    config := Config{
        Username: newUsername,
        Password: newPassword,
    }

    err = writeConfig(config)
    if err != nil {
        http.Error(w, "Error updating configuration", http.StatusInternalServerError)
        return
    }

    fmt.Fprintln(w, "Credentials updated successfully")
}

func handleVMStatus(w http.ResponseWriter, r *http.Request) {
    vmStatuses, err := getVMStatuses()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(vmStatuses) 

}

func getVMStatuses() ([]VMStatus, error) {
    cmd := exec.Command("virsh", "list", "--all")
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        return nil, fmt.Errorf("failed to execute virsh list command: %v", err)
    }

    lines := strings.Split(out.String(), "\n")
    var vmStatuses []VMStatus
    for _, line := range lines[2 : len(lines)-2] { // Skip header and footer lines
        fields := strings.Fields(line)
        if len(fields) >= 3 {
            vmStatuses = append(vmStatuses, VMStatus{
                Name:   fields[1],
                Status: fields[2],
            })
        }
    }

    return vmStatuses, nil
}

func handleVMReset(w http.ResponseWriter, r *http.Request) {
    vmName := r.URL.Query().Get("name")
    if vmName == "" {
        http.Error(w, "Missing VM name", http.StatusBadRequest)
        return
    }

    err := resetVM(vmName)
    if err != nil {
        http.Error(w, "Failed to reset VM: "+err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Fprintln(w, "VM reset initiated")
}

func handleVMShutdown(w http.ResponseWriter, r *http.Request) {
    vmName := r.URL.Query().Get("name")
    if vmName == "" {
        http.Error(w, "Missing VM name", http.StatusBadRequest)
        return
    }

    err := shutdownVM(vmName)
    if err != nil {
        http.Error(w, "Failed to shutdown VM: "+err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Fprintln(w, "VM shutdown initiated")
}

func handleVMInfo(w http.ResponseWriter, r *http.Request) {
    vmName := r.URL.Query().Get("name")
    if vmName == "" {
        http.Error(w, "Missing VM name", http.StatusBadRequest)
        return
    }

    vmInfo, err := getVMInfo(vmName)
    if err != nil {
        http.Error(w, "Failed to get VM info: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(vmInfo)
}

func resetVM(vmName string) error {
    cmd := exec.Command("virsh", "reset", vmName)
    return cmd.Run() 
}

func shutdownVM(vmName string) error {
    cmd := exec.Command("virsh", "shutdown", vmName)
    return cmd.Run() 
}

func getVMInfo(vmName string) (map[string]string, error) {
    cmd := exec.Command("virsh", "dominfo", vmName)
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        return nil, fmt.Errorf("failed to execute virsh dominfo command: %v", err)
    }

    vmInfo := make(map[string]string)
    lines := strings.Split(out.String(), "\n")
    for _, line := range lines {
        if strings.Contains(line, ":") {
            parts := strings.SplitN(line, ":", 2)
            key := strings.TrimSpace(parts[0])
            value := strings.TrimSpace(parts[1])
            vmInfo[key] = value
        }
    }

    return vmInfo, nil
}
