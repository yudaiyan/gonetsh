package netsh

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"errors"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	utilexec "k8s.io/utils/exec"
)

// Interface is an injectable interface for running netsh commands.  Implementations must be goroutine-safe.
type Interface interface {
	// EnsurePortProxyRule checks if the specified redirect exists, if not creates it
	EnsurePortProxyRule(args []string) (bool, error)
	// DeletePortProxyRule deletes the specified portproxy rule.  If the rule did not exist, return error.
	DeletePortProxyRule(args []string) error
	// DeleteIPAddress checks if the specified IP address is present and, if so, deletes it.
	DeleteIPAddress(args []string) error
	// Restore runs `netsh exec` to restore portproxy or addresses using a file.
	// TODO Check if this is required, most likely not
	Restore(args []string) error
	// Get the interface name that has the default gateway
	GetDefaultGatewayIfaceName() (string, error)
	// Get a list of interfaces and addresses
	GetInterfaces() ([]Ipv4Interface, error)
	// Gets an interface by name
	GetInterfaceByName(name string) (Ipv4Interface, error)
	// Gets an interface by ip address in the format a.b.c.d
	GetInterfaceByIP(ipAddr string) (Ipv4Interface, error)
	// 设置静态ip, 会替换当前网卡的静态ip
	// ip 格式 10.0.0.2/24
	SetIPAddress(iface string, address string) error
	// 添加ip
	AddIPAddress(iface string, address string) error
	// Enable forwarding on the interface (name or index)
	EnableForwarding(iface string) error
	// Set the DNS server for interface
	SetDNSServer(iface string, dns string) error
}

const (
	cmdNetsh string = "netsh"
)

// runner implements Interface in terms of exec("netsh").
type runner struct {
	exec utilexec.Interface
}

// Ipv4Interface models IPv4 interface output from: netsh interface ipv4 show addresses
type Ipv4Interface struct {
	Idx                   int
	Name                  string
	InterfaceMetric       int
	DhcpEnabled           bool
	IpAddress             string
	SubnetPrefix          int
	GatewayMetric         int
	DefaultGatewayAddress string
	DNS                   string
}

// New returns a new Interface which will exec netsh.
func New(exec utilexec.Interface) Interface {

	if exec == nil {
		exec = utilexec.New()
	}

	runner := &runner{
		exec: exec,
	}
	return runner
}

func (runner *runner) GetInterfaces() ([]Ipv4Interface, error) {
	interfaces, interfaceError := runner.getIpAddressConfigurations()

	if interfaceError != nil {
		return nil, interfaceError
	}

	indexMap, indexError := runner.getNetworkInterfaceParameters()

	if indexError != nil {
		return nil, indexError
	}

	// zip them up
	for i := 0; i < len(interfaces); i++ {
		name := interfaces[i].Name

		if val, ok := indexMap[name]; ok {
			interfaces[i].Idx = val
		} else {
			return nil, fmt.Errorf("no index found for interface \"%v\"", name)
		}
	}

	return interfaces, nil
}

func GB2312toUTF8(gb2312Str string) string {
	decoder := simplifiedchinese.GB18030.NewDecoder()
	utf8Data, _, _ := transform.Bytes(decoder, []byte(gb2312Str))
	return string(utf8Data)
}

// GetInterfaces uses the show addresses command and returns a formatted structure
func (runner *runner) getIpAddressConfigurations() ([]Ipv4Interface, error) {
	args := []string{
		"interface", "ipv4", "show", "config",
	}

	output, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput()
	if err != nil {
		return nil, err
	}
	interfacesString := GB2312toUTF8(string(output[:]))
	outputLines := strings.Split(interfacesString, "\r\n")

	var interfaces []Ipv4Interface
	var currentInterface Ipv4Interface
	quotedPattern := regexp.MustCompile(`接口 "(.+)" 的配置`)
	cidrPattern := regexp.MustCompile(`\/(.*?)\ `)

	for _, outputLine := range outputLines {
		if match := quotedPattern.FindStringSubmatch(outputLine); len(match) > 0 {
			if currentInterface != (Ipv4Interface{}) {
				interfaces = append(interfaces, currentInterface)
			}
			currentInterface = Ipv4Interface{
				Name: match[1],
			}
		} else {
			parts := strings.SplitN(outputLine, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if strings.HasPrefix(key, "DHCP 已启用") {
				if value == "是" {
					currentInterface.DhcpEnabled = true
				}
			} else if strings.HasPrefix(key, "InterfaceMetric") {
				if val, err := strconv.Atoi(value); err == nil {
					currentInterface.InterfaceMetric = val
				}
			} else if strings.HasPrefix(key, "网关跃点数") {
				if val, err := strconv.Atoi(value); err == nil {
					currentInterface.GatewayMetric = val
				}
			} else if strings.HasPrefix(key, "子网前缀") {
				match := cidrPattern.FindStringSubmatch(value)
				if val, err := strconv.Atoi(match[1]); err == nil {
					currentInterface.SubnetPrefix = val
				}
			} else if strings.HasPrefix(key, "IP 地址") {
				currentInterface.IpAddress = value
			} else if strings.HasPrefix(key, "默认网关") {
				currentInterface.DefaultGatewayAddress = value
			} else if strings.HasPrefix(key, "通过 DHCP 配置的 DNS 服务器") {
				currentInterface.DNS = value
			}
		}
	}

	// add the last one
	if currentInterface != (Ipv4Interface{}) {
		interfaces = append(interfaces, currentInterface)
	}

	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces found in netsh output: %v", interfacesString)
	}

	return interfaces, nil
}

func (runner *runner) getNetworkInterfaceParameters() (map[string]int, error) {
	args := []string{
		"interface", "ipv4", "show", "interfaces",
	}

	output, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput()

	if err != nil {
		return nil, err
	}

	// Split output by line
	outputString := GB2312toUTF8(string(output[:]))
	outputString = strings.TrimSpace(outputString)
	var outputLines = strings.Split(outputString, "\r\n")

	if len(outputLines) < 3 {
		return nil, errors.New("unexpected netsh output:\n" + outputString)
	}

	// Remove first two lines of header text
	outputLines = outputLines[2:]

	indexMap := make(map[string]int)

	reg := regexp.MustCompile(`\s{2,}`)

	for _, line := range outputLines {

		line = strings.TrimSpace(line)

		// Split the line by two or more whitespace characters, returning all substrings (n < 0)
		splitLine := reg.Split(line, -1)

		name := splitLine[4]
		if idx, err := strconv.Atoi(splitLine[0]); err == nil {
			indexMap[name] = idx
		}

	}

	return indexMap, nil
}

// Enable forwarding on the interface (name or index)
func (runner *runner) EnableForwarding(iface string) error {
	args := []string{
		"int", "ipv4", "set", "int", strconv.Quote(iface), "for=en",
	}
	cmd := strings.Join(args, " ")
	if stdout, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable forwarding on [%v], error: %v. cmd: %v. stdout: %v", iface, err.Error(), cmd, string(stdout))
	}

	return nil
}

// EnsurePortProxyRule checks if the specified redirect exists, if not creates it.
func (runner *runner) EnsurePortProxyRule(args []string) (bool, error) {
	out, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput()

	if err == nil {
		return true, nil
	}
	if ee, ok := err.(utilexec.ExitError); ok {
		// netsh uses exit(0) to indicate a success of the operation,
		// as compared to a malformed commandline, for example.
		if ee.Exited() && ee.ExitStatus() != 0 {
			return false, nil
		}
	}
	return false, fmt.Errorf("error checking portproxy rule: %v: %s", err, out)

}

// DeletePortProxyRule deletes the specified portproxy rule.  If the rule did not exist, return error.
func (runner *runner) DeletePortProxyRule(args []string) error {
	out, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput()

	if err == nil {
		return nil
	}
	if ee, ok := err.(utilexec.ExitError); ok {
		// netsh uses exit(0) to indicate a success of the operation,
		// as compared to a malformed commandline, for example.
		if ee.Exited() && ee.ExitStatus() == 0 {
			return nil
		}
	}
	return fmt.Errorf("error deleting portproxy rule: %v: %s", err, out)
}

// DeleteIPAddress checks if the specified IP address is present and, if so, deletes it.
func (runner *runner) DeleteIPAddress(args []string) error {
	out, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput()

	if err == nil {
		return nil
	}
	if ee, ok := err.(utilexec.ExitError); ok {
		// netsh uses exit(0) to indicate a success of the operation,
		// as compared to a malformed commandline, for example.
		if ee.Exited() && ee.ExitStatus() == 0 {
			return nil
		}
	}
	return fmt.Errorf("error deleting ipv4 address: %v: %s", err, out)
}

func (runner *runner) GetDefaultGatewayIfaceName() (string, error) {
	interfaces, err := runner.GetInterfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.DefaultGatewayAddress != "" {
			return iface.Name, nil
		}
	}

	// return "not found"
	return "", fmt.Errorf("default interface not found")
}

func (runner *runner) GetInterfaceByName(name string) (Ipv4Interface, error) {
	interfaces, err := runner.GetInterfaces()
	if err != nil {
		return Ipv4Interface{}, err
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			return iface, nil
		}
	}

	// return "not found"
	return Ipv4Interface{}, fmt.Errorf("Interface not found: %v", name)
}

func (runner *runner) GetInterfaceByIP(ipAddr string) (Ipv4Interface, error) {
	interfaces, err := runner.GetInterfaces()
	if err != nil {
		return Ipv4Interface{}, err
	}

	for _, iface := range interfaces {
		if iface.IpAddress == ipAddr {
			return iface, nil
		}
	}

	// return "not found"
	return Ipv4Interface{}, fmt.Errorf("Interface not found: %v", ipAddr)
}

func (runner *runner) SetDNSServer(iface string, dns string) error {
	args := []string{
		"int", "ipv4", "set", "dns", strconv.Quote(iface), "static", strconv.Quote(dns),
	}
	cmd := strings.Join(args, " ")
	if stdout, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set dns on [%v], error: %v. cmd: %v. stdout: %v", iface, err.Error(), cmd, string(stdout))
	}

	return nil
}

func (runner *runner) SetIPAddress(iface string, address string) error {
	ip, ipnet, _ := net.ParseCIDR(address)
	ipAddress := ip.String()
	subnetMask := net.IP(ipnet.Mask).String()

	args := []string{
		"int", "ipv4", "add", "address", strconv.Quote(iface), "static", ipAddress, subnetMask,
	}
	cmd := strings.Join(args, " ")
	fmt.Printf("exec cmd: %s %s\n", cmdNetsh, cmd)
	if stdout, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set ip on [%v], error: %v. cmd: %v. stdout: %v", iface, err.Error(), cmd, string(stdout))
	}
	return nil
}

func (runner *runner) AddIPAddress(iface string, address string) error {
	ip, ipnet, _ := net.ParseCIDR(address)
	ipAddress := ip.String()
	subnetMask := net.IP(ipnet.Mask).String()

	args := []string{
		"int", "ipv4", "add", "address", strconv.Quote(iface), ipAddress, subnetMask,
	}
	cmd := strings.Join(args, " ")
	fmt.Printf("exec cmd: %s %s\n", cmdNetsh, cmd)
	if stdout, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set ip on [%v], error: %v. cmd: %v. stdout: %v", iface, err.Error(), cmd, string(stdout))
	}
	return nil
}

// Restore is part of Interface.
func (runner *runner) Restore(args []string) error {
	return nil
}
