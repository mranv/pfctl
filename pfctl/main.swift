//
//  main.swift
//  pfctl
//
//  Created by Anubhav Gain on 07/04/24.
//
import Foundation

func readIPAndPortFromFile(fileURL: URL) -> (String, String) {
    guard let xmlContent = try? String(contentsOf: fileURL) else {
        fatalError("Failed to read file at: \(fileURL.path)")
    }
    
    let regex = try! NSRegularExpression(pattern: "<address>(.*?)</address>.*?<port>(.*?)</port>", options: [.dotMatchesLineSeparators])
    let matches = regex.matches(in: xmlContent, range: NSRange(xmlContent.startIndex..., in: xmlContent))
    
    guard let match = matches.first else {
        fatalError("IP address or port not found in the configuration file.")
    }
    
    let ipRange = Range(match.range(at: 1), in: xmlContent)!
    let portRange = Range(match.range(at: 2), in: xmlContent)!
    
    let ip = xmlContent[ipRange].trimmingCharacters(in: .whitespacesAndNewlines)
    let port = xmlContent[portRange].trimmingCharacters(in: .whitespacesAndNewlines)
    
    return (ip, port)
}

func updateConfigFileWithTimestamp(fileURL: URL, timestamp: String) {
    guard var xmlContent = try? String(contentsOf: fileURL) else {
        fatalError("Failed to read file at: \(fileURL.path)")
    }
    
    let insertionPoint = xmlContent.range(of: "</ossec_config>")
    guard let insertionIndex = insertionPoint?.lowerBound else {
        fatalError("Failed to find insertion point in the configuration file.")
    }
    
    let newLabel = """
    \n<labels>
      <label key="firewall.stop-time">\(timestamp)</label>
    </labels>
    """
    
    xmlContent.insert(contentsOf: newLabel, at: insertionIndex)
    
    do {
        try xmlContent.write(to: fileURL, atomically: true, encoding: .utf8)
    } catch {
        fatalError("Failed to write updated content to file at: \(fileURL.path)")
    }
}

func configurePFCTL(ip: String, port: String) {
    // Run pfctl commands to configure firewall rules
    let pfctlProcess = Process()
    pfctlProcess.launchPath = "/sbin/pfctl"
    
    // Enable packet filtering
    pfctlProcess.arguments = ["-E"]
    pfctlProcess.launch()
    pfctlProcess.waitUntilExit()
    
    // Add rules for inbound and outbound traffic
    let addRulesProcess = Process()
    addRulesProcess.launchPath = "/sbin/pfctl"
    addRulesProcess.arguments = ["-q", "-f", "-"]
    
    let ruleString = """
    rdr pass inet proto tcp from any to any port \(port) -> \(ip) port \(port)
    pass out proto tcp from any to \(ip) port \(port)
    pass in proto tcp from \(ip) port \(port) to any
    """
    
    addRulesProcess.standardInput = Pipe()
    addRulesProcess.standardOutput = Pipe()
    
    if let inputPipe = addRulesProcess.standardInput as? Pipe {
        inputPipe.fileHandleForWriting.write(ruleString.data(using: .utf8)!)
        inputPipe.fileHandleForWriting.closeFile()
    }
    
    addRulesProcess.launch()
    addRulesProcess.waitUntilExit()
    
    if addRulesProcess.terminationStatus == 0 {
        print("PFCTL rules configured successfully.")
    } else {
        print("Failed to configure PFCTL rules.")
    }
}

func main() {
    let fileURL = URL(fileURLWithPath: "/Library/Ossec/etc/ossec.conf")
    
    // Read IP address and port from the file
    let (ip, port) = readIPAndPortFromFile(fileURL: fileURL)
    
    // Get the current time as timestamp
    let dateFormatter = DateFormatter()
    dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
    let currentTime = dateFormatter.string(from: Date())
    
    // Update the configuration file with the timestamp
    updateConfigFileWithTimestamp(fileURL: fileURL, timestamp: currentTime)
    
    // Perform operations using pfctl
    // Configure pfctl with IP and port
    configurePFCTL(ip: ip, port: port)
    
    // Print confirmation message
    print("Configuration updated with timestamp: \(currentTime)")
}

// Call the main function to start the program
main()
