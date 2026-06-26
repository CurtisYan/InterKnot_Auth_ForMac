import Foundation

enum AppSection: String, CaseIterable, Identifiable {
    case dashboard = "概览"
    case accounts = "账号"
    case network = "认证参数"
    case multiLogin = "多拨"
    case tunnel = "隧道"

    var id: String { rawValue }
}

enum RequiredField: Hashable {
    case username
    case password
    case esurfingURL
    case wlanACIP
    case wlanUserIP

    var title: String {
        switch self {
        case .username: return "账号"
        case .password: return "密码"
        case .esurfingURL: return "ESurfing URL"
        case .wlanACIP: return "WLAN AC IP"
        case .wlanUserIP: return "本机 IP"
        }
    }
}

enum LoginMode: String, Codable, CaseIterable, Identifiable {
    case automatic = "自动识别"
    case teacher = "教师/t 模式"

    var id: String { rawValue }
}

enum ConnectionState: Equatable {
    case idle
    case loggingIn
    case loggingOut
    case connected(String)
    case failed(String)

    var title: String {
        switch self {
        case .idle:
            return "未连接"
        case .loggingIn:
            return "登录中"
        case .loggingOut:
            return "注销中"
        case .connected:
            return "已连接"
        case .failed:
            return "连接失败"
        }
    }

    var detail: String {
        switch self {
        case .idle:
            return "等待认证"
        case .loggingIn:
            return "正在和 ESurfing 网关通信"
        case .loggingOut:
            return "正在下线"
        case .connected(let message):
            return message
        case .failed(let message):
            return message
        }
    }
}

struct MultiLoginAccount: Identifiable, Codable, Equatable {
    var id: UUID = UUID()
    var enabled: Bool = true
    var label: String = ""
    var username: String = ""
    var password: String = ""
    var userIP: String = ""
}

struct EasyTierSettings: Codable, Equatable {
    var binaryPath: String = ""
    var secretKey: String = "Hello_InterKnot"
    var peerAddress: String = ""
    var virtualIP: String = ""
    var enableIPv6: Bool = false
    var enableWebDownload: Bool = true
}

struct AppSettings: Codable, Equatable {
    var username: String = ""
    var savePassword: Bool = true
    var autoConnect: Bool = false
    var enableWatchdog: Bool = true
    var autoShare: Bool = false
    var autoUpdateUserIP: Bool = false
    var loginMode: LoginMode = .automatic

    var esurfingURL: String = "enet.10000.gd.cn:10001"
    var wlanACIP: String = "0.0.0.0"
    var wlanUserIP: String = "0.0.0.0"
    var watchdogTimeout: Int = 5
    var probeURLs: [String] = [
        "https://www.apple.com/library/test/success.html",
        "https://www.baidu.com",
        "https://www.qq.com"
    ]

    var rsaPublicKey: String = AppSettings.defaultRSAPublicKey
    var multiAccounts: [MultiLoginAccount] = []
    var easyTier: EasyTierSettings = EasyTierSettings()

    static let empty = AppSettings()

    static let defaultRSAPublicKey = """
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyhncn4Z4RY8wITqV7n6hAapEM
    ZwNBP6fflsGs3Ke5g6Ji4AWvNflIXZLNTGIuykoU1v2Bitylyuc9nSKLTvBdcytB
    +4X4CvV4oVDr2aLrXs7LhTNyykcxyhyGhokph0Cb4yR/mybK6OeH2ME1/AZS7AZ4
    pe2gw9lcwXQVF8DJwwIDAQAB
    -----END PUBLIC KEY-----
    """
}

struct CaptchaChallenge: Identifiable {
    let id = UUID()
    let imageData: Data
}

struct LogEntry: Identifiable {
    let id = UUID()
    let date = Date()
    let level: String
    let message: String
}

struct LoginRequest {
    var username: String
    var password: String
    var userIP: String
    var mode: LoginMode
}

struct LoginResult {
    var success: Bool
    var message: String
    var signature: String?
}

struct CampusParameters {
    var esurfingURL: String
    var wlanACIP: String
    var wlanUserIP: String
}

struct ProbeResult: Identifiable, Equatable {
    let id = UUID()
    let target: String
    let success: Bool
    let latencyMS: Int?
    let statusCode: Int?
    let message: String
    let checkedAt: Date
}
