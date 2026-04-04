package collector

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// SystemInfo holds the basic host identity data.
type SystemInfo struct {
	Hostname string
	OS       string
	IP       string
}

// Package represents an installed OS package.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

// GetSystemInfo collects hostname, OS, and primary outbound IP.
func GetSystemInfo() (*SystemInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %v", err)
	}

	ip, err := getOutboundIP()
	if err != nil {
		ip = net.ParseIP("127.0.0.1")
	}

	return &SystemInfo{
		Hostname: hostname,
		OS:       runtime.GOOS + "/" + runtime.GOARCH,
		IP:       ip.String(),
	}, nil
}

// getOutboundIP returns the primary outbound IP without sending any traffic.
func getOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

// GetInstalledPackages returns a list of installed packages for CVE correlation.
// Supports Debian/Ubuntu (dpkg) and RHEL/Fedora (rpm). Returns empty list on unsupported systems.
func GetInstalledPackages() []Package {
	switch runtime.GOOS {
	case "linux":
		if pkgs := parseDpkg(); len(pkgs) > 0 {
			return pkgs
		}
		return parseRpm()
	default:
		return nil
	}
}

// parseDpkg reads /var/lib/dpkg/status (Debian-based systems).
func parseDpkg() []Package {
	f, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return nil
	}
	defer f.Close()

	var packages []Package
	var current Package
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Package: ") {
			current.Name = strings.TrimPrefix(line, "Package: ")
		} else if strings.HasPrefix(line, "Version: ") {
			current.Version = strings.TrimPrefix(line, "Version: ")
		} else if strings.HasPrefix(line, "Architecture: ") {
			current.Arch = strings.TrimPrefix(line, "Architecture: ")
		} else if line == "" && current.Name != "" {
			packages = append(packages, current)
			current = Package{}
		}
	}
	if current.Name != "" {
		packages = append(packages, current)
	}
	return packages
}

// parseRpm queries the rpm database (RHEL-based systems).
func parseRpm() []Package {
	out, err := exec.Command("rpm", "-qa", "--queryformat", "%{NAME} %{VERSION} %{ARCH}\n").Output()
	if err != nil {
		return nil
	}
	var packages []Package
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			packages = append(packages, Package{Name: parts[0], Version: parts[1], Arch: parts[2]})
		}
	}
	return packages
}
