import Foundation

// MARK: - Logger

final class Logger {
    private static let queue = DispatchQueue(label: "com.interknot.logger")
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
        }
    }
    
    static func clear() {
        try? "".write(to: logURL, atomically: true, encoding: .utf8)
    }
}
