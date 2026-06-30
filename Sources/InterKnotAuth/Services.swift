import Foundation
import Network
import Security

enum AppError: LocalizedError {
    case invalidURL(String)
    case missingBinary(String)
    case rsaKeyUnavailable
    case requestFailed(String)

    var errorDescription: String? {
        switch self {
        case .invalidURL(let url):
            return "无效 URL：\(url)"
        case .missingBinary(let path):
            return "找不到可执行文件：\(path)"
        case .rsaKeyUnavailable:
            return "RSA 公钥不可用，请在认证参数中填写或确认网关页面提供公钥"
        case .requestFailed(let message):
            return message
        }
    }
}

final class ConfigStore {
    private let fileURL: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("InterKnotAuth", isDirectory: true)
        fileURL = base.appendingPathComponent("settings.json")
    }

    func load() -> AppSettings {
        if let data = try? Data(contentsOf: fileURL),
           var settings = try? JSONDecoder().decode(AppSettings.self, from: data) {
            if settings.rsaPublicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                settings.rsaPublicKey = AppSettings.defaultRSAPublicKey
                save(settings)
            }
            return settings
        }
        return migrateLegacyConfig() ?? .empty
    }

    func save(_ settings: AppSettings) {
        do {
            try FileManager.default.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            let data = try JSONEncoder.pretty.encode(settings)
            try data.write(to: fileURL, options: .atomic)
        } catch {
            Logger.write("[ERROR] Save settings failed: \(error)")
        }
    }

    private func migrateLegacyConfig() -> AppSettings? {
        let legacyPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/SAC/config.ini")
        guard let text = try? String(contentsOf: legacyPath, encoding: .utf8) else {
            return nil
        }

        let dict = Dictionary(uniqueKeysWithValues: text
            .components(separatedBy: .newlines)
            .compactMap { line -> (String, String)? in
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty, !trimmed.hasPrefix("#"), !trimmed.hasPrefix(";") else { return nil }
                let parts = trimmed.split(separator: "=", maxSplits: 1).map(String.init)
                guard parts.count == 2 else { return nil }
                return (parts[0].lowercased(), parts[1])
            })

        var settings = AppSettings.empty
        settings.username = dict["username"] ?? ""
        settings.esurfingURL = dict["esurfingurl"] ?? ""
        settings.wlanACIP = dict["wlanacip"] ?? "0.0.0.0"
        settings.wlanUserIP = dict["wlanuserip"] ?? "0.0.0.0"
        settings.savePassword = dict["save_pwd"] != "0"
        settings.autoConnect = dict["auto_connect"] == "1"
        settings.enableWatchdog = dict["enable_watch_dog"] != "0"
        settings.autoShare = dict["auto_share"] == "1"
        settings.autoUpdateUserIP = dict["auto_update_userip"] == "1"
        settings.watchdogTimeout = Int(dict["wtg_timeout"] ?? "") ?? 5
        settings.loginMode = dict["login_mode"] == "1" ? .teacher : .automatic
        settings.easyTier.secretKey = dict["et_secret_key"] ?? "Hello_InterKnot"
        settings.easyTier.enableIPv6 = dict["et_enable_ipv6"] == "1"
        settings.easyTier.enableWebDownload = dict["et_enable_webdl"] != "0"
        save(settings)
        return settings
    }
}

final class CredentialStore {
    private let service = "InterKnotAuth"

    func save(password: String, for account: String) {
        guard let data = password.data(using: .utf8), !account.isEmpty else { return }
        delete(account: account)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    func password(for account: String) -> String? {
        guard !account.isEmpty else { return nil }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    func delete(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

final class AuthenticationService {
    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 8
        configuration.httpCookieStorage = .shared
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        session = URLSession(configuration: configuration)
    }

    func login(
        request: LoginRequest,
        settings: AppSettings,
        captchaProvider: @escaping (Data, String?) async -> String?,
        logger: @escaping (String) -> Void
    ) async throws -> LoginResult {
        let base = normalizeBaseURL(settings.esurfingURL)
        let pageURL = try url("\(base)/qs/index_gz.jsp?wlanacip=\(settings.wlanACIP.urlFormEscaped)&wlanuserip=\(request.userIP.urlFormEscaped)")
        logger("获取广东天翼认证页面：\(pageURL.absoluteString)")
        let pageHTML = try await fetchText(pageURL)
        guard let captchaURL = extractCaptchaURL(from: pageHTML, pageURL: pageURL) else {
            return LoginResult(success: false, message: "未找到验证码图片，请检查 ESurfing URL、WLAN AC IP 和本机 IP", signature: nil)
        }

        var captchaCode = ""
        logger("获取验证码")
        let imageData = try await fetchData(captchaURL)
        let recognition = CaptchaService.recognizeDetailed(imageData: imageData)
        if let recognition, recognition.isReliable {
            captchaCode = recognition.text
            logger("验证码自动识别：\(captchaCode)")
        } else if let manual = await captchaProvider(imageData, recognition?.text) {
            if let recognition {
                logger("验证码识别候选：\(recognition.text)，请确认")
            }
            captchaCode = sanitizeCaptcha(manual)
            logger("使用手动验证码")
        } else {
            return LoginResult(success: false, message: "验证码未填写", signature: nil)
        }

        let loginKey = try buildLoginKey(
            request: request,
            settings: settings,
            captcha: captchaCode
        )
        let endpoint = try url("\(base)/ajax/login")
        logger("提交登录请求")
        var loginHeaders = [
            "Origin": base,
            "Referer": pageURL.absoluteString
        ]
        if let cookieHeader = cookieHeader(for: endpoint, extra: ["loginUser": request.username]) {
            loginHeaders["Cookie"] = cookieHeader
        }
        let response = try await postForm(
            endpoint,
            payload: [
                "loginKey": loginKey,
                "wlanuserip": request.userIP,
                "wlanacip": settings.wlanACIP
            ],
            headers: loginHeaders
        )
        return classifyLoginResponse(response.text, cookies: response.cookies)
    }

    func logout(settings: AppSettings, userIP: String, account: String, signature: String) async throws -> String {
        let base = normalizeBaseURL(settings.esurfingURL)
        let endpoint = try url("\(base)/ajax/logout")
        let response = try await postForm(
            endpoint,
            payload: [
                "wlanuserip": userIP,
                "wlanacip": settings.wlanACIP
            ],
            headers: [
                "Cookie": "signature=\(signature); loginUser=\(account)"
            ]
        )
        return try classifyLogoutResponse(response.text)
    }

    func detectParameters() async throws -> CampusParameters {
        let target = try url("http://189.cn/")
        var request = URLRequest(url: target)
        request.timeoutInterval = 3
        let (_, response) = try await session.data(for: request)
        guard let finalURL = (response as? HTTPURLResponse)?.url?.absoluteString else {
            throw AppError.requestFailed("没有收到广东天翼重定向 URL")
        }
        return try parseParameters(from: finalURL)
    }

    func parseParameters(from redirectURL: String) throws -> CampusParameters {
        let trimmed = redirectURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw AppError.requestFailed("请输入 2.2.2.2 跳转后的完整地址")
        }
        guard let components = URLComponents(string: trimmed),
              let host = components.host else {
            throw AppError.requestFailed("无法识别跳转地址")
        }

        let port = components.port.map { ":\($0)" } ?? ""
        let esurfingURL = "\(host)\(port)"
        let queryItems = components.queryItems ?? []
        let wlanACIP = queryItems.first { $0.name.lowercased() == "wlanacip" }?.value
        let wlanUserIP = queryItems.first { $0.name.lowercased() == "wlanuserip" }?.value

        guard let wlanACIP, !wlanACIP.isEmpty,
              let wlanUserIP, !wlanUserIP.isEmpty else {
            throw AppError.requestFailed("跳转地址中没有 wlanacip 或 wlanuserip")
        }

        return CampusParameters(esurfingURL: esurfingURL, wlanACIP: wlanACIP, wlanUserIP: wlanUserIP)
    }

    private func fetchText(_ url: URL) async throws -> String {
        let data = try await fetchData(url)
        return String(data: data, encoding: .utf8) ?? String(data: data, encoding: .gb18030) ?? ""
    }

    private func fetchData(_ url: URL) async throws -> Data {
        var request = URLRequest(url: url)
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        guard let status = (response as? HTTPURLResponse)?.statusCode, (200..<400).contains(status) else {
            throw AppError.requestFailed("HTTP 请求失败：\(url.absoluteString)")
        }
        return data
    }

    private func postForm(_ url: URL, payload: [String: String], headers: [String: String] = [:]) async throws -> (text: String, cookies: [HTTPCookie]) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("application/x-www-form-urlencoded; charset=UTF-8", forHTTPHeaderField: "Content-Type")
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        request.httpBody = payload.formURLEncoded.data(using: .utf8)

        let (data, response) = try await session.data(for: request)
        guard let status = (response as? HTTPURLResponse)?.statusCode, (200..<500).contains(status) else {
            throw AppError.requestFailed("登录接口无响应")
        }
        let text = String(data: data, encoding: .utf8) ?? ""
        let cookies = (response as? HTTPURLResponse)
            .flatMap { HTTPCookie.cookies(withResponseHeaderFields: $0.allHeaderFields as? [String: String] ?? [:], for: url) } ?? []
        return (text, cookies)
    }

    private func buildLoginKey(
        request: LoginRequest,
        settings: AppSettings,
        captcha: String
    ) throws -> String {
        let compactJSON = "{\"userName\":\"\(request.username.jsonEscaped)\",\"password\":\"\(request.password.jsonEscaped)\",\"rand\":\"\(captcha.jsonEscaped)\"}"
        guard compactJSON.utf8.count <= 117 else {
            throw AppError.requestFailed("账号或密码过长，无法放入 1024-bit RSA 明文块")
        }
        return try encryptRSAHex(compactJSON, settings: settings)
    }

    private func classifyLoginResponse(_ response: String, cookies: [HTTPCookie]) -> LoginResult {
        let signature = cookies.first { $0.name == "signature" }?.value
        if let data = response.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let code = String(describing: json["resultCode"] ?? "")
            let info = String(describing: json["resultInfo"] ?? "认证成功")
            if code == "0" {
                return LoginResult(success: true, message: info, signature: signature)
            }
            if code == "13002000" {
                return LoginResult(success: true, message: "账号已在线", signature: signature)
            }
            return LoginResult(success: false, message: "\(info)（\(code)）", signature: nil)
        }
        if response.isEmpty {
            return LoginResult(success: false, message: "网关返回空响应", signature: nil)
        }
        return LoginResult(success: false, message: response, signature: nil)
    }

    private func classifyLogoutResponse(_ response: String) throws -> String {
        guard !response.isEmpty else {
            throw AppError.requestFailed("网关返回空响应")
        }
        if let data = response.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let code = String(describing: json["resultCode"] ?? "")
            let info = String(describing: json["resultInfo"] ?? "下线成功")
            if code == "0" || code == "13002000" {
                return "下线成功"
            }
            throw AppError.requestFailed("\(info)（\(code)）")
        }
        throw AppError.requestFailed(response)
    }

    private func sanitizeCaptcha(_ value: String) -> String {
        value
            .filter { $0.isLetter || $0.isNumber }
            .prefix(4)
            .map(String.init)
            .joined()
    }

    private func extractCaptchaURL(from html: String, pageURL: URL) -> URL? {
        let patterns = [
            #"/common/image_code\.jsp\?time=\d+"#,
            #"src=["']([^"']*(?:captcha|Captcha|vcode|image_code)[^"']*)["']"#,
            #"<img[^>]+src=["']([^"']+)["']"#
        ]
        for pattern in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { continue }
            let range = NSRange(html.startIndex..<html.endIndex, in: html)
            guard let match = regex.firstMatch(in: html, range: range) else { continue }
            let group = match.numberOfRanges > 1 ? 1 : 0
            guard let capture = Range(match.range(at: group), in: html) else { continue }
            return URL(string: String(html[capture]), relativeTo: pageURL)?.absoluteURL
        }
        return nil
    }

    private func encryptRSAHex(_ value: String, settings: AppSettings) throws -> String {
        let pem = settings.rsaPublicKey
        guard !pem.isEmpty else { throw AppError.rsaKeyUnavailable }
        guard let key = SecKey.publicKey(fromPEM: pem) else {
            throw AppError.rsaKeyUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            key,
            .rsaEncryptionPKCS1,
            Data(value.utf8) as CFData,
            &error
        ) as Data? else {
            if let error = error?.takeRetainedValue() {
                throw error as Error
            }
            throw AppError.rsaKeyUnavailable
        }
        return encrypted.hexString
    }

    private func normalizeBaseURL(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://") {
            return trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        }
        return "http://\(trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "/")))"
    }

    private func url(_ string: String) throws -> URL {
        guard let url = URL(string: string) else { throw AppError.invalidURL(string) }
        return url
    }

    private func firstCapture(pattern: String, in text: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, range: range),
              let capture = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[capture])
    }

    private func cookieHeader(for url: URL, extra: [String: String]) -> String? {
        var cookies: [String: String] = [:]
        let storedCookies = session.configuration.httpCookieStorage?.cookies(for: url) ?? []
        for cookie in storedCookies {
            cookies[cookie.name] = cookie.value
        }
        for (key, value) in extra {
            cookies[key] = value
        }
        guard !cookies.isEmpty else { return nil }
        return cookies
            .map { "\($0.key)=\($0.value)" }
            .sorted()
            .joined(separator: "; ")
    }

    private var userAgent: String {
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 InterKnotAuth/2.0"
    }
}

final class ConnectivityProbeService {
    func measure(urlStrings: [String]) async -> [ProbeResult] {
        var results: [ProbeResult] = []
        for item in urlStrings where !item.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            results.append(await measure(urlString: item))
        }
        return results
    }

    private func measure(urlString: String) async -> ProbeResult {
        let normalized = urlString.hasPrefix("http://") || urlString.hasPrefix("https://")
            ? urlString
            : "https://\(urlString)"
        guard let url = URL(string: normalized) else {
            return ProbeResult(
                target: urlString,
                success: false,
                latencyMS: nil,
                statusCode: nil,
                message: "URL 无效",
                checkedAt: Date()
            )
        }

        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        request.timeoutInterval = 5
        let start = Date()
        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            let elapsed = Int(Date().timeIntervalSince(start) * 1000)
            let code = (response as? HTTPURLResponse)?.statusCode
            let ok = code.map { (200..<500).contains($0) } ?? false
            return ProbeResult(
                target: normalized,
                success: ok,
                latencyMS: elapsed,
                statusCode: code,
                message: ok ? "可达" : "HTTP 异常",
                checkedAt: Date()
            )
        } catch {
            return ProbeResult(
                target: normalized,
                success: false,
                latencyMS: nil,
                statusCode: nil,
                message: error.localizedDescription,
                checkedAt: Date()
            )
        }
    }
}

final class WatchdogService {
    private let timeout: Int
    private let probeURLs: [String]
    private let hasLocalIP: () -> Bool
    private let reconnect: () -> Void
    private let logger: (String) -> Void
    private var task: Task<Void, Never>?

    init(
        timeout: Int,
        probeURLs: [String],
        hasLocalIP: @escaping () -> Bool,
        reconnect: @escaping () -> Void,
        logger: @escaping (String) -> Void
    ) {
        self.timeout = max(timeout, 3)
        self.probeURLs = probeURLs
        self.hasLocalIP = hasLocalIP
        self.reconnect = reconnect
        self.logger = logger
    }

    func start() {
        task?.cancel()
        task = Task {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(timeout) * 1_000_000_000)
                guard hasLocalIP() else { continue }
                let reachable = await anyProbeReachable()
                if !reachable {
                    logger("检测点全部不可达")
                    reconnect()
                }
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    private func anyProbeReachable() async -> Bool {
        for item in probeURLs {
            guard let url = URL(string: item) else { continue }
            var request = URLRequest(url: url)
            request.httpMethod = "HEAD"
            request.timeoutInterval = 3
            if let (_, response) = try? await URLSession.shared.data(for: request),
               let code = (response as? HTTPURLResponse)?.statusCode,
               (200..<500).contains(code) {
                return true
            }
        }
        return false
    }
}

final class EasyTierService {
    private var process: Process?

    func startServer(settings: EasyTierSettings, logger: @escaping (String) -> Void) throws {
        try start(arguments: serverArguments(settings), settings: settings, logger: logger)
    }

    func startClient(settings: EasyTierSettings, logger: @escaping (String) -> Void) throws {
        try start(arguments: clientArguments(settings), settings: settings, logger: logger)
    }

    func stop() {
        process?.terminate()
        process = nil
    }

    private func start(arguments: [String], settings: EasyTierSettings, logger: @escaping (String) -> Void) throws {
        stop()
        guard !settings.binaryPath.isEmpty,
              FileManager.default.isExecutableFile(atPath: settings.binaryPath) else {
            throw AppError.missingBinary(settings.binaryPath.isEmpty ? "easytier-core" : settings.binaryPath)
        }

        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: settings.binaryPath)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            logger(text.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        try process.run()
        self.process = process
    }

    private func serverArguments(_ settings: EasyTierSettings) -> [String] {
        var args = ["--network-name", "InterKnot", "--network-secret", settings.secretKey]
        if settings.enableIPv6 { args.append("--enable-ipv6") }
        if !settings.virtualIP.isEmpty {
            args += ["--ipv4", settings.virtualIP]
        }
        return args
    }

    private func clientArguments(_ settings: EasyTierSettings) -> [String] {
        var args = serverArguments(settings)
        if !settings.peerAddress.isEmpty {
            args += ["--peers", settings.peerAddress]
        }
        return args
    }
}

final class LocalWebServer {
    private var listener: NWListener?

    func start(port: UInt16, htmlProvider: @escaping () -> String) throws {
        stop()
        let listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: port)!)
        listener.newConnectionHandler = { connection in
            connection.start(queue: .global(qos: .utility))
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
                let body = htmlProvider()
                let response = """
                HTTP/1.1 200 OK\r
                Content-Type: text/html; charset=utf-8\r
                Content-Length: \(body.data(using: .utf8)?.count ?? 0)\r
                Connection: close\r
                \r
                \(body)
                """
                connection.send(content: response.data(using: .utf8), completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }
        listener.start(queue: .global(qos: .utility))
        self.listener = listener
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }
}

enum NetworkInterfaceService {
    static func localIPv4Address() -> String? {
        var interfaces: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&interfaces) == 0, let first = interfaces else { return nil }
        defer { freeifaddrs(interfaces) }

        var pointer: UnsafeMutablePointer<ifaddrs>? = first
        while let current = pointer {
            defer { pointer = current.pointee.ifa_next }
            let flags = Int32(current.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 else { continue }
            guard current.pointee.ifa_addr.pointee.sa_family == UInt8(AF_INET) else { continue }

            let name = String(cString: current.pointee.ifa_name)
            guard name.hasPrefix("en") || name.hasPrefix("bridge") || name.hasPrefix("utun") else { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(
                current.pointee.ifa_addr,
                socklen_t(current.pointee.ifa_addr.pointee.sa_len),
                &host,
                socklen_t(host.count),
                nil,
                0,
                NI_NUMERICHOST
            )
            guard result == 0 else { continue }
            let ip = String(cString: host)
            if !ip.isEmpty { return ip }
        }
        return nil
    }
}

private extension JSONEncoder {
    static var pretty: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}

private extension String.Encoding {
    static let gb18030 = String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(CFStringEncoding(CFStringEncodings.GB_18030_2000.rawValue)))
}

private extension Dictionary where Key == String, Value == String {
    var formURLEncoded: String {
        map { key, value in
            "\(key.urlFormEscaped)=\(value.urlFormEscaped)"
        }
        .sorted()
        .joined(separator: "&")
    }
}

extension String {
    var urlFormEscaped: String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&+=?/;:@")
        return addingPercentEncoding(withAllowedCharacters: allowed) ?? self
    }

    var jsonEscaped: String {
        replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
    }
}

private extension SecKey {
    static func publicKey(fromPEM pem: String) -> SecKey? {
        let base64 = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .components(separatedBy: .whitespacesAndNewlines)
            .joined()
        guard let data = Data(base64Encoded: base64) else { return nil }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 1024
        ]
        return SecKeyCreateWithData(data as CFData, attributes as CFDictionary, nil)
    }
}
