import Foundation

// MARK: - Logger

final class Logger {
    private static let queue = DispatchQueue(label: "com.interknot.logger")
    private static let maxLogBytes = 512 * 1024
    private static let trimToBytes = 384 * 1024
    private static let trimCheckInterval = 64
    private static var writesSinceTrim = 0
    private static let logURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("InterKnotAuth", isDirectory: true)
        .appendingPathComponent("log.txt")
    
    static func write(_ text: String) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let line = "[\(timestamp)] \(text)\n"
        
        queue.async {
            try? FileManager.default.createDirectory(
                at: logURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            
            if let handle = try? FileHandle(forWritingTo: logURL) {
                handle.seekToEndOfFile()
                if let data = line.data(using: String.Encoding.utf8) {
                    handle.write(data)
                }
                handle.closeFile()
            } else {
                try? line.write(to: logURL, atomically: true, encoding: .utf8)
            }

            writesSinceTrim += 1
            if writesSinceTrim >= trimCheckInterval {
                writesSinceTrim = 0
                trimIfNeeded()
            }
        }
    }
    
    static func clear() {
        queue.async {
            try? "".write(to: logURL, atomically: true, encoding: .utf8)
            writesSinceTrim = 0
        }
    }

    private static func trimIfNeeded() {
        guard let size = (try? FileManager.default.attributesOfItem(atPath: logURL.path)[.size]) as? NSNumber,
              size.intValue > maxLogBytes,
              let data = try? Data(contentsOf: logURL) else {
            return
        }

        let suffix = data.suffix(trimToBytes)
        let trimmed: Data
        if let newlineIndex = suffix.firstIndex(of: UInt8(ascii: "\n")) {
            trimmed = Data(suffix[suffix.index(after: newlineIndex)...])
        } else {
            trimmed = Data(suffix)
        }
        try? trimmed.write(to: logURL, options: .atomic)
    }
}
