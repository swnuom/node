package main

import (
    "fmt"
    "net"
)

func generateLinkLocalIPv6(macAddress net.HardwareAddr) string {
    // Ensure the MAC address has 6 bytes.
    if len(macAddress) != 6 {
        return ""
    }

    // Create the link-local IPv6 address using the "fe80::" prefix and the MAC address.
    linkLocalIPv6 := fmt.Sprintf("fe80::%02x%02x:%02xff:fe%02x:%02x%02x",
        macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5])

    return linkLocalIPv6
}

func main() {
    // Replace "eno1" with the name of the network interface you want to retrieve the MAC address for.
    ifaceName := "eno1"

    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        fmt.Printf("Error retrieving network interface: %v\n", err)
        return
    }

    macAddr := iface.HardwareAddr
    fmt.Printf("MAC Address of %s: %s\n", ifaceName, macAddr)

    // Generate the link-local IPv6 address based on the retrieved MAC address.
    linkLocalIPv6 := generateLinkLocalIPv6(macAddr)

    if linkLocalIPv6 == "" {
        fmt.Println("Failed to generate link-local IPv6 address.")
        return
    }

    fmt.Printf("Generated Link-Local IPv6 Address: %s\n", linkLocalIPv6)
}

