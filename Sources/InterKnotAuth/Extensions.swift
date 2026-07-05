import Foundation

// MARK: - Shared Extensions

extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

extension String {
    var sanitizedAccountIdentifier: String {
        unicodeScalars
            .filter { scalar in
                ("0"..."9").contains(scalar)
                    || ("A"..."Z").contains(scalar)
                    || ("a"..."z").contains(scalar)
            }
            .map(String.init)
            .joined()
    }
}
