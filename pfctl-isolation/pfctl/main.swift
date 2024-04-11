//
//  main.swift
//  pfctl
//
//  Created by Anubhav Gain on 07/04/24.
import Foundation

// Function to read IP address and port from file
func readIPAndPortFromFile(filePath: String) -> (String, String)? {
    guard let content = try? String(contentsOfFile: filePath) else {
        print("Failed to read file at path: \(filePath)")
        return nil
    }
    
    guard let ipRange = content.range(of: "<address>(.*?)</address>", options: .regularExpression),
          let portRange = content.range(of: "<port>(.*?)</port>", options: .regularExpression) else {
        print("IP address or port not found in file at path: \(filePath)")
        return nil
    }
    
    let ip = String(content[ipRange]).replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression, range: nil).trimmingCharacters(in: .whitespacesAndNewlines)
    let port = String(content[portRange]).replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression, range: nil).trimmingCharacters(in: .whitespacesAndNewlines)
    
    return (ip, port)
}

// Function to update configuration file with timestamp
func updateConfigFileWithTimestamp(filePath: String, timestamp: String) {
    guard var content = try? String(contentsOfFile: filePath) else {
        print("Failed to read file at path: \(filePath)")
        return
    }
    
    guard let insertionPoint = content.range(of: "</ossec_config>") else {
        print("Insertion point not found in file at path: \(filePath)")
        return
    }
    
    let newContent = "\n<labels>\n  <label key=\"isolated.time\">\(timestamp)</label>\n</labels>\n"
    content.insert(contentsOf: newContent, at: insertionPoint.lowerBound)
    
    do {
        try content.write(toFile: filePath, atomically: true, encoding: .utf8)
        print("File updated with timestamp at path: \(filePath)")
    } catch {
        print("Failed to update file at path: \(filePath). Error: \(error)")
    }
}

// Function to disable pf firewall
func disablePF() {
    let disablePF = Process()
    disablePF.launchPath = "/sbin/pfctl"
    disablePF.arguments = ["-d"] // Disable pf firewall
    disablePF.launch()
}

// Function to verify rules
func verifyRules() {
    let verifyRules = Process()
    verifyRules.launchPath = "/sbin/pfctl"
    verifyRules.arguments = ["-sr"]
    verifyRules.launch()
}

// Function to enable pf firewall
func enablePF() {
    let enablePF = Process()
    enablePF.launchPath = "/sbin/pfctl"
    enablePF.arguments = ["-e"] // Enable pf firewall
    enablePF.launch()
}

func main() {
    guard let (ip, port) = readIPAndPortFromFile(filePath: "/Library/Ossec/etc/ossec.conf") else {
        return
    }
    
    let currentDateTime = Date()
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
    let timestamp = formatter.string(from: currentDateTime)
    
    updateConfigFileWithTimestamp(filePath: "/Library/Ossec/etc/ossec.conf", timestamp: timestamp)
    
    disablePF()
    print("Packet filter disabled.")
    
    let rulesContent = """
    block all
    pass in inet proto tcp from \(ip) to any port \(port)
    pass out inet proto tcp from any to \(ip) port \(port)
    """
    
    let rulesFilePath = "/tmp/pf.rules"
    do {
        try rulesContent.write(toFile: rulesFilePath, atomically: true, encoding: .utf8)
    } catch {
        print("Failed to write rules file at path: \(rulesFilePath). Error: \(error)")
        return
    }
    
    // Instead of directly loading rules with '-f' option, we'll append rules to pf.conf and reload
    let appendRules = Process()
    appendRules.launchPath = "/bin/sh"
    appendRules.arguments = ["-c", "echo '\(rulesContent)' >> /etc/pf.conf && /sbin/pfctl -f /etc/pf.conf"]
    appendRules.launch()
    
    verifyRules()
    
    enablePF()
    print("Packet filter enabled.")
    
    print("Packet filter configured with rules based on the IP address \(ip) and port \(port) from the file /Library/Ossec/etc/ossec.conf.")
}

// Call the main function
main()
