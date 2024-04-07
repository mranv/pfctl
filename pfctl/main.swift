//
//  main.swift
//  pfctl
//
//  Created by Anubhav Gain on 07/04/24.

import Foundation

func readIPAndPortFromFile(filePath: String) -> (String, String)? {
    // Read the contents of the file
    guard let content = try? String(contentsOfFile: filePath) else {
        print("Failed to read file")
        return nil
    }
    
    // Extract IP address and port from the content
    guard let ipRange = content.range(of: "<address>(.*?)</address>", options: .regularExpression),
          let portRange = content.range(of: "<port>(.*?)</port>", options: .regularExpression) else {
        print("IP address or port not found in file")
        return nil
    }
    
    let ip = String(content[ipRange]).replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression, range: nil).trimmingCharacters(in: .whitespacesAndNewlines)
    let port = String(content[portRange]).replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression, range: nil).trimmingCharacters(in: .whitespacesAndNewlines)
    
    return (ip, port)
}

func updateConfigFileWithTimestamp(filePath: String, timestamp: String) {
    // Read contents of the file
    guard var content = try? String(contentsOfFile: filePath) else {
        print("Failed to read file")
        return
    }
    
    // Find the position to insert the label
    guard let insertionPoint = content.range(of: "</ossec_config>") else {
        print("Insertion point not found")
        return
    }
    
    // Insert the label with the timestamp
    let newContent = "\n<labels>\n  <label key=\"isolated.time\">\(timestamp)</label>\n</labels>\n"
    content.insert(contentsOf: newContent, at: insertionPoint.lowerBound)
    
    // Write the updated content to the file
    do {
        try content.write(toFile: filePath, atomically: true, encoding: .utf8)
        print("File updated with timestamp")
    } catch {
        print("Failed to update file: \(error)")
    }
}

// Main function
func main() {
    // Read IP address and port from the file
    guard let (ip, port) = readIPAndPortFromFile(filePath: "/Library/Ossec/etc/ossec.conf") else {
        return
    }
    
    // Get the current time as timestamp
    let currentDateTime = Date()
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
    let timestamp = formatter.string(from: currentDateTime)
    
    // Update the configuration file with the timestamp
    updateConfigFileWithTimestamp(filePath: "/Library/Ossec/etc/ossec.conf", timestamp: timestamp)
    
    // Configure packet filter using pfctl
    
    // Enable packet filter
    let enablePfctl = Process()
    enablePfctl.launchPath = "/sbin/pfctl"
    enablePfctl.arguments = ["-e"]
    enablePfctl.launch()
    
    // Configure rules for inbound and outbound traffic
    let configureRules1 = Process()
    configureRules1.launchPath = "/sbin/pfctl"
    configureRules1.arguments = ["-a", "anchorname", "-p", "tcp", "-s", ip, "--dport", port, "-j", "pass"]
    configureRules1.launch()
    
    let configureRules2 = Process()
    configureRules2.launchPath = "/sbin/pfctl"
    configureRules2.arguments = ["-a", "anchorname", "-p", "tcp", "-d", ip, "--sport", port, "-j", "pass"]
    configureRules2.launch()
    
    print("Packet filter configured with rules based on the IP address \(ip) and port \(port) from the file /Library/Ossec/etc/ossec.conf.")
}

// Call the main function
main()
