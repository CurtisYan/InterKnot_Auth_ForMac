import CommonCrypto
import CryptoKit
import Foundation

struct StudentDialerLoginResult {
    let result: LoginResult
    let userIP: String
    let acIP: String
}

final class StudentDialerService: NSObject, URLSessionTaskDelegate {
    static let signatureMarker = "__student_client_session__"

    private static let userAgent = "CCTP/android64_vpn/2093"
    private static let accept = "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*"
    private static let captiveURL = "http://connect.rom.miui.com/generate_204"
    private static let portalStart = "<!--//config.campus.js.chinatelecom.com"
    private static let portalEnd = "//config.campus.js.chinatelecom.com-->"
    private static let initialAlgoID = "00000000-0000-0000-0000-000000000000"

    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 20
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()
    private var activeSession: StudentSession?
    private var heartbeatTask: Task<Void, Never>?

    var canTerminateActiveSession: Bool {
        activeSession?.termURL.isEmpty == false
    }

    override init() {
        super.init()
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    func login(request: LoginRequest, logger: @escaping (String) -> Void) async throws -> StudentDialerLoginResult {
        stopHeartbeat()
        if let state = activeSession, !state.termURL.isEmpty {
            logger("学生端：复用本程序已建立的客户端会话")
            startHeartbeat(logger: logger)
            return StudentDialerLoginResult(
                result: LoginResult(success: true, message: "学生端会话已连接", signature: Self.signatureMarker),
                userIP: state.config.userIP,
                acIP: state.config.acIP
            )
        }
        logger("学生端：检测客户端认证配置")
        let clientID = UUID().uuidString.lowercased()
        let configStatus = try await detectConfig(clientID: clientID)
        guard case .requiresAuthorization(let config) = configStatus else {
            logger("学生端：当前网络已联网，未返回客户端认证配置")
            return StudentDialerLoginResult(
                result: LoginResult(success: true, message: "学生端检测到当前网络已连接；如果不是本程序建立的会话，将不能使用本程序主动下线", signature: nil),
                userIP: request.userIP,
                acIP: ""
            )
        }
        logger("学生端：认证 IP \(config.userIP)，AC IP \(config.acIP)")

        var state = StudentSession(
            config: config,
            clientID: config.clientID,
            macAddress: Self.randomMACAddress(),
            hostName: Self.randomString(length: 10),
            algoID: Self.initialAlgoID,
            cipher: nil,
            ticket: "",
            keepURL: "",
            termURL: "",
            keepRetry: 30
        )

        logger("学生端：初始化加密会话")
        let zsm = try await postBytes(url: config.ticketURL, body: state.algoID, state: state)
        state.cipher = try StudentCipherFactory.makeCipher(from: zsm, algoID: &state.algoID)
        logger("学生端：使用算法 \(state.algoID)")

        state.ticket = try await fetchTicket(state: state)
        guard !state.ticket.isEmpty else {
            return StudentDialerLoginResult(
                result: LoginResult(success: false, message: "学生端登录失败：未获取到 ticket", signature: nil),
                userIP: config.userIP,
                acIP: config.acIP
            )
        }

        let loginPayload = """
        <?xml version="1.0" encoding="utf-8"?>
        <request>
            <user-agent>\(Self.userAgent)</user-agent>
            <client-id>\(state.clientID)</client-id>
            <ticket>\(state.ticket)</ticket>
            <local-time>\(Self.localTime())</local-time>
            <userid>\(request.username)</userid>
            <passwd>\(request.password)</passwd>
        </request>
        """
        let loginText = try await encryptedPostXML(url: config.authURL, payload: loginPayload, state: state)
        state.keepURL = Self.firstXMLValue("keep-url", in: loginText) ?? ""
        state.termURL = Self.firstXMLValue("term-url", in: loginText) ?? ""
        if let retry = Self.firstXMLValue("keep-retry", in: loginText).flatMap(Int.init), retry > 0 {
            state.keepRetry = retry
        }

        guard !state.keepURL.isEmpty else {
            let message = Self.firstXMLValue("message", in: loginText)
                ?? Self.firstXMLValue("result", in: loginText)
                ?? "学生端登录失败：未返回 keep-url"
            return StudentDialerLoginResult(
                result: LoginResult(success: false, message: message, signature: nil),
                userIP: config.userIP,
                acIP: config.acIP
            )
        }

        activeSession = state
        startHeartbeat(logger: logger)
        return StudentDialerLoginResult(
            result: LoginResult(success: true, message: "学生端登录成功", signature: Self.signatureMarker),
            userIP: config.userIP,
            acIP: config.acIP
        )
    }

    func logout(logger: @escaping (String) -> Void) async throws -> String {
        stopHeartbeat()
        guard let state = activeSession, !state.termURL.isEmpty else {
            activeSession = nil
            return "学生端本地会话已停止；当前没有 term-url，无法主动通知网关下线"
        }
        let payload = keepAlivePayload(state: state)
        _ = try await encryptedPostXML(url: state.termURL, payload: payload, state: state)
        activeSession = nil
        logger("学生端：已发送下线请求")
        return "学生端下线请求已发送"
    }

    func stopHeartbeat() {
        heartbeatTask?.cancel()
        heartbeatTask = nil
    }

    private func startHeartbeat(logger: @escaping (String) -> Void) {
        guard let state = activeSession else { return }
        heartbeatTask?.cancel()
        heartbeatTask = Task { [weak self] in
            var currentState = state
            while !Task.isCancelled {
                let delay = max(currentState.keepRetry, 10)
                try? await Task.sleep(nanoseconds: UInt64(delay) * 1_000_000_000)
                guard !Task.isCancelled else { return }
                do {
                    let payload = self?.keepAlivePayload(state: currentState) ?? ""
                    if let text = try await self?.encryptedPostXML(url: currentState.keepURL, payload: payload, state: currentState),
                       let interval = Self.firstXMLValue("interval", in: text).flatMap(Int.init),
                       interval > 0 {
                        currentState.keepRetry = interval
                    }
                    logger("学生端：心跳成功，下一次 \(currentState.keepRetry) 秒")
                } catch {
                    logger("学生端：心跳失败：\(error.localizedDescription)")
                    return
                }
            }
        }
    }

    private func detectConfig(clientID: String) async throws -> StudentConfigStatus {
        guard let url = URL(string: Self.captiveURL) else {
            throw AppError.invalidURL(Self.captiveURL)
        }
        var request = URLRequest(url: url)
        request.setValue(Self.userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(Self.accept, forHTTPHeaderField: "Accept")
        request.setValue(clientID, forHTTPHeaderField: "Client-ID")
        let (data, response, redirectContext) = try await sendFollowingRedirects(request: request, context: StudentRedirectContext())
        guard (200..<400).contains(response.statusCode) else {
            throw AppError.requestFailed("学生端配置检测失败")
        }
        let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .gb18030Student) ?? ""
        guard let portal = Self.extractBetween(Self.portalStart, Self.portalEnd, in: text), !portal.isEmpty else {
            return .connected
        }
        guard let configURLs = Self.extractConfigURLs(from: portal),
              let ticketComponents = URLComponents(string: configURLs.ticketURL) else {
            throw AppError.requestFailed("学生端：认证配置缺少 auth-url 或 ticket-url（\(Self.responseSummary(portal))）")
        }
        let queryItems = ticketComponents.queryItems ?? []
        guard let userIP = queryItems.first(where: { $0.name.lowercased() == "wlanuserip" })?.value,
              let acIP = queryItems.first(where: { $0.name.lowercased() == "wlanacip" })?.value,
              !userIP.isEmpty,
              !acIP.isEmpty else {
            throw AppError.requestFailed("学生端：ticket-url 缺少 wlanuserip 或 wlanacip")
        }
        return .requiresAuthorization(
            StudentCampusConfig(
                clientID: clientID,
                authURL: configURLs.authURL,
                ticketURL: configURLs.ticketURL,
                userIP: userIP,
                acIP: acIP,
                redirectContext: redirectContext
            )
        )
    }

    private func fetchTicket(state: StudentSession) async throws -> String {
        let payload = """
        <?xml version="1.0" encoding="utf-8"?>
        <request>
            <user-agent>\(Self.userAgent)</user-agent>
            <client-id>\(state.clientID)</client-id>
            <local-time>\(Self.localTime())</local-time>
            <host-name>\(state.hostName)</host-name>
            <ipv4>\(state.config.userIP)</ipv4>
            <ipv6></ipv6>
            <mac>\(state.macAddress)</mac>
            <ostag>\(state.hostName)</ostag>
            <gwip>\(state.config.acIP)</gwip>
        </request>
        """
        let text = try await encryptedPostXML(url: state.config.ticketURL, payload: payload, state: state)
        return Self.firstXMLValue("ticket", in: text) ?? ""
    }

    private func keepAlivePayload(state: StudentSession) -> String {
        """
        <?xml version="1.0" encoding="utf-8"?>
        <request>
            <user-agent>\(Self.userAgent)</user-agent>
            <client-id>\(state.clientID)</client-id>
            <local-time>\(Self.localTime())</local-time>
            <host-name>\(state.hostName)</host-name>
            <ipv4>\(state.config.userIP)</ipv4>
            <ticket>\(state.ticket)</ticket>
            <ipv6></ipv6>
            <mac>\(state.macAddress)</mac>
            <ostag>\(state.hostName)</ostag>
        </request>
        """
    }

    private func encryptedPostXML(url: String, payload: String, state: StudentSession) async throws -> String {
        guard let cipher = state.cipher else {
            throw AppError.requestFailed("学生端加密会话未初始化")
        }
        let encrypted = try cipher.encrypt(payload)
        let data = try await postBytes(url: url, body: encrypted, state: state)
        let response = String(data: data, encoding: .utf8) ?? ""
        return try cipher.decrypt(response)
    }

    private func postBytes(url: String, body: String, state: StudentSession) async throws -> Data {
        guard let endpoint = URL(string: url) else {
            throw AppError.invalidURL(url)
        }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue(Self.userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(Self.accept, forHTTPHeaderField: "Accept")
        request.setValue(Self.md5Hex(body), forHTTPHeaderField: "CDC-Checksum")
        request.setValue(state.clientID, forHTTPHeaderField: "Client-ID")
        request.setValue(state.algoID, forHTTPHeaderField: "Algo-ID")
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = body.data(using: .utf8)
        let (data, response, _) = try await sendFollowingRedirects(request: request, context: state.config.redirectContext)
        guard (200..<500).contains(response.statusCode) else {
            throw AppError.requestFailed("学生端接口无响应")
        }
        return data
    }

    private func sendFollowingRedirects(
        request initialRequest: URLRequest,
        context initialContext: StudentRedirectContext
    ) async throws -> (Data, HTTPURLResponse, StudentRedirectContext) {
        var request = initialRequest
        var context = initialContext
        for _ in 0..<6 {
            context.apply(to: &request)
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw AppError.requestFailed("学生端接口响应无效")
            }
            context.update(from: http)
            guard (300..<400).contains(http.statusCode),
                  let location = http.value(forHTTPHeaderField: "Location"),
                  let nextURL = URL(string: location, relativeTo: request.url)?.absoluteURL else {
                return (data, http, context)
            }
            var next = request
            next.url = nextURL
            next.setValue(Self.userAgent, forHTTPHeaderField: "User-Agent")
            next.setValue(Self.accept, forHTTPHeaderField: "Accept")
            context.apply(to: &next)
            request = next
        }
        throw AppError.requestFailed("学生端接口重定向过多")
    }

    private static func extractBetween(_ start: String, _ end: String, in text: String) -> String? {
        guard let startRange = text.range(of: start),
              let endRange = text.range(of: end, range: startRange.upperBound..<text.endIndex) else {
            return nil
        }
        return String(text[startRange.upperBound..<endRange.lowerBound])
    }

    private static func extractConfigURLs(from portal: String) -> (authURL: String, ticketURL: String)? {
        let decodedPortal = portal.htmlEntityDecoded
        guard let authURL = firstConfigValue(names: ["auth-url", "authUrl"], in: decodedPortal),
              let ticketURL = firstConfigValue(names: ["ticket-url", "ticketUrl"], in: decodedPortal) else {
            return nil
        }
        return (authURL, ticketURL)
    }

    private static func firstConfigValue(names: [String], in text: String) -> String? {
        for name in names {
            if let value = firstXMLValue(name, in: text) {
                return value
            }
            if let value = firstKeyValue(name, in: text) {
                return value
            }
        }
        return nil
    }

    private static func firstXMLValue(_ tag: String, in text: String) -> String? {
        let pattern = "<\(NSRegularExpression.escapedPattern(for: tag))[^>]*>\\s*([^<]*)\\s*</\(NSRegularExpression.escapedPattern(for: tag))>"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, range: range),
              match.numberOfRanges > 1,
              let captureRange = Range(match.range(at: 1), in: text) else {
            return nil
        }
        return String(text[captureRange]).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func firstKeyValue(_ key: String, in text: String) -> String? {
        let escapedKey = NSRegularExpression.escapedPattern(for: key)
        let pattern = #"(?i)(?:["']?\#(escapedKey)["']?\s*[:=]\s*)(["'])(.*?)\1"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, range: range),
              match.numberOfRanges > 2,
              let captureRange = Range(match.range(at: 2), in: text) else {
            return nil
        }
        let value = String(text[captureRange]).trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    private static func responseSummary(_ text: String) -> String {
        let collapsed = text
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return String(collapsed.prefix(180))
    }

    private static func localTime() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        formatter.timeZone = TimeZone(secondsFromGMT: 8 * 3600)
        return formatter.string(from: Date())
    }

    private static func randomString(length: Int) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        return String((0..<length).compactMap { _ in alphabet.randomElement() })
    }

    private static func randomMACAddress() -> String {
        var bytes = (0..<6).map { _ in UInt8.random(in: 0...255) }
        bytes[0] &= 0xFE
        return bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    private static func md5Hex(_ text: String) -> String {
        let data = Data(text.utf8)
        return Insecure.MD5.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
    }
}

private extension String {
    var htmlEntityDecoded: String {
        var decoded = self
        for (entity, value) in [
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&quot;", "\""),
            ("&#39;", "'"),
            ("&apos;", "'"),
            ("&amp;", "&")
        ] {
            decoded = decoded.replacingOccurrences(of: entity, with: value, options: [.caseInsensitive])
        }
        return decoded
    }
}

private struct StudentCampusConfig {
    let clientID: String
    let authURL: String
    let ticketURL: String
    let userIP: String
    let acIP: String
    let redirectContext: StudentRedirectContext
}

private enum StudentConfigStatus {
    case connected
    case requiresAuthorization(StudentCampusConfig)
}

private struct StudentRedirectContext {
    var schoolID: String = ""
    var domain: String = ""
    var area: String = ""

    mutating func update(from response: HTTPURLResponse) {
        if let value = response.value(forHTTPHeaderField: "schoolid"), !value.isEmpty {
            schoolID = value
        }
        if let value = response.value(forHTTPHeaderField: "domain"), !value.isEmpty {
            domain = value
        }
        if let value = response.value(forHTTPHeaderField: "area"), !value.isEmpty {
            area = value
        }
    }

    func apply(to request: inout URLRequest) {
        if !schoolID.isEmpty {
            request.setValue(schoolID, forHTTPHeaderField: "CDC-SchoolId")
        }
        if !domain.isEmpty {
            request.setValue(domain, forHTTPHeaderField: "CDC-Domain")
        }
        if !area.isEmpty {
            request.setValue(area, forHTTPHeaderField: "CDC-Area")
        }
    }
}

private struct StudentSession {
    var config: StudentCampusConfig
    var clientID: String
    var macAddress: String
    var hostName: String
    var algoID: String
    var cipher: StudentCipher?
    var ticket: String
    var keepURL: String
    var termURL: String
    var keepRetry: Int
}

private protocol StudentCipher {
    var algoID: String { get }
    func encrypt(_ text: String) throws -> String
    func decrypt(_ hex: String) throws -> String
}

private enum StudentCipherFactory {
    static func makeCipher(from zsm: Data, algoID: inout String) throws -> StudentCipher {
        let bytes = [UInt8](zsm)
        guard bytes.count >= 4 else {
            throw AppError.requestFailed("学生端：会话初始化数据无效")
        }
        let keyLength = Int(bytes[3])
        var pos = 4 + keyLength
        guard pos < bytes.count else {
            throw AppError.requestFailed("学生端：会话初始化数据缺少算法信息")
        }
        let algoLength = Int(bytes[pos])
        pos += 1
        guard pos + algoLength <= bytes.count else {
            throw AppError.requestFailed("学生端：算法信息长度无效")
        }
        algoID = String(data: Data(bytes[pos..<(pos + algoLength)]), encoding: .utf8) ?? ""

        switch algoID {
        case "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E":
            return StudentCommonCryptoCipher(algoID: algoID, algorithm: CCAlgorithm(kCCAlgorithmAES), blockSize: 16, mode: .cbcWithPrependedIV, key1: Keys.aesCBCKey1, key2: Keys.aesCBCKey2, iv: Keys.aesCBCIV)
        case "A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4":
            return StudentCommonCryptoCipher(algoID: algoID, algorithm: CCAlgorithm(kCCAlgorithmAES), blockSize: 16, mode: .ecb, key1: Keys.aesECBKey1, key2: Keys.aesECBKey2, iv: [])
        case "5BFBA864-BBA9-42DB-8EAD-49B5F412BD81":
            return StudentCommonCryptoCipher(algoID: algoID, algorithm: CCAlgorithm(kCCAlgorithm3DES), blockSize: 16, mode: .cbc, key1: Keys.desCBCKey1, key2: Keys.desCBCKey2, iv: Keys.desCBCIV)
        case "6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5":
            return StudentCommonCryptoCipher(algoID: algoID, algorithm: CCAlgorithm(kCCAlgorithm3DES), blockSize: 16, mode: .ecb, key1: Keys.desECBKey1, key2: Keys.desECBKey2, iv: [])
        case "B3047D4E-67DF-4864-A6A5-DF9B9E525C79":
            return StudentModXTEACipher(algoID: algoID, key1: Keys.xteaKey1, key2: Keys.xteaKey2, key3: Keys.xteaKey3)
        case "C32C68F9-CA81-4260-A329-BBAFD1A9CCD1":
            return StudentModXTEAIVCipher(algoID: algoID, key1: Keys.xteaIVKey1, key2: Keys.xteaIVKey2, key3: Keys.xteaIVKey3, iv: Keys.xteaIV)
        case "F3974434-C0DD-4C20-9E87-DDB6814A1C48", "ED382482-F72C-4C41-A76D-28EEA0F1F2AF", "B809531F-0007-4B5B-923B-4BD560398113":
            throw AppError.requestFailed("学生端：当前学校下发算法 \(algoID)，Swift 原生 SM4/ZUC 支持尚未完成")
        default:
            throw AppError.requestFailed("学生端：未知加密算法 \(algoID)")
        }
    }
}

private struct StudentCommonCryptoCipher: StudentCipher {
    enum Mode {
        case ecb
        case cbc
        case cbcWithPrependedIV
    }

    let algoID: String
    let algorithm: CCAlgorithm
    let blockSize: Int
    let mode: Mode
    let key1: [UInt8]
    let key2: [UInt8]
    let iv: [UInt8]

    func encrypt(_ text: String) throws -> String {
        let r1 = try cryptEncrypt([UInt8](text.utf8), key: key1)
        let r2 = try cryptEncrypt(r1, key: key2)
        return r2.hexUpper
    }

    func decrypt(_ hex: String) throws -> String {
        let bytes = try [UInt8](hexString: hex)
        let decryptInput = mode == .cbcWithPrependedIV ? Array(bytes.dropFirst(iv.count)) : bytes
        let r1 = try cryptDecrypt(decryptInput, key: key2)
        let r2Input = mode == .cbcWithPrependedIV ? Array(r1.dropFirst(iv.count)) : r1
        let r2 = try cryptDecrypt(r2Input, key: key1).trimmedZeroSuffix()
        return String(decoding: r2, as: UTF8.self)
    }

    private func cryptEncrypt(_ bytes: [UInt8], key: [UInt8]) throws -> [UInt8] {
        let padded = bytes.padded(toMultipleOf: blockSize)
        let encrypted = try crypt(padded, key: key, operation: CCOperation(kCCEncrypt))
        return mode == .cbcWithPrependedIV ? iv + encrypted : encrypted
    }

    private func cryptDecrypt(_ bytes: [UInt8], key: [UInt8]) throws -> [UInt8] {
        try crypt(bytes, key: key, operation: CCOperation(kCCDecrypt))
    }

    private func crypt(_ bytes: [UInt8], key: [UInt8], operation: CCOperation) throws -> [UInt8] {
        var output = [UInt8](repeating: 0, count: bytes.count + blockSize)
        var outputLength = 0
        let options = mode == .ecb ? CCOptions(kCCOptionECBMode) : CCOptions(0)
        let status = bytes.withUnsafeBytes { dataBuffer in
            key.withUnsafeBytes { keyBuffer in
                iv.withUnsafeBytes { ivBuffer in
                    CCCrypt(
                        operation,
                        algorithm,
                        options,
                        keyBuffer.baseAddress,
                        key.count,
                        mode == .ecb ? nil : ivBuffer.baseAddress,
                        dataBuffer.baseAddress,
                        bytes.count,
                        &output,
                        output.count,
                        &outputLength
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw AppError.requestFailed("学生端加解密失败：\(status)")
        }
        return Array(output.prefix(outputLength))
    }
}

private class StudentModXTEABase {
    private let rounds = 32
    private let delta: UInt32 = 0x9E3779B9

    func encryptBlock(_ v0In: UInt32, _ v1In: UInt32, key: [UInt32]) -> (UInt32, UInt32) {
        var v0 = v0In
        var v1 = v1In
        var sum: UInt32 = 0
        for _ in 0..<rounds {
            v0 &+= (v1 ^ sum) &+ key[Int(sum & 3)] &+ ((v1 &<< 4) ^ (v1 &>> 5))
            sum &+= delta
            v1 &+= key[Int((sum &>> 11) & 3)] &+ (v0 ^ sum) &+ ((v0 &<< 4) ^ (v0 &>> 5))
        }
        return (v0, v1)
    }

    func decryptBlock(_ v0In: UInt32, _ v1In: UInt32, key: [UInt32]) -> (UInt32, UInt32) {
        var v0 = v0In
        var v1 = v1In
        var sum = delta &* UInt32(rounds)
        for _ in 0..<rounds {
            v1 &-= key[Int((sum &>> 11) & 3)] &+ (v0 ^ sum) &+ ((v0 &<< 4) ^ (v0 &>> 5))
            sum &-= delta
            v0 &-= (v1 ^ sum) &+ key[Int(sum & 3)] &+ ((v1 &<< 4) ^ (v1 &>> 5))
        }
        return (v0, v1)
    }
}

private final class StudentModXTEACipher: StudentModXTEABase, StudentCipher {
    let algoID: String
    private let key1: [UInt32]
    private let key2: [UInt32]
    private let key3: [UInt32]

    init(algoID: String, key1: [UInt32], key2: [UInt32], key3: [UInt32]) {
        self.algoID = algoID
        self.key1 = key1
        self.key2 = key2
        self.key3 = key3
    }

    func encrypt(_ text: String) throws -> String {
        var blocks = [UInt8](text.utf8).padded(toMultipleOf: 8)
        for offset in stride(from: 0, to: blocks.count, by: 8) {
            let v0 = blocks.uint32BE(at: offset)
            let v1 = blocks.uint32BE(at: offset + 4)
            let r1 = encryptBlock(v0, v1, key: key1)
            let r2 = encryptBlock(r1.0, r1.1, key: key2)
            let r3 = encryptBlock(r2.0, r2.1, key: key3)
            blocks.setUInt32BE(r3.0, at: offset)
            blocks.setUInt32BE(r3.1, at: offset + 4)
        }
        return blocks.hexUpper
    }

    func decrypt(_ hex: String) throws -> String {
        var blocks = try [UInt8](hexString: hex)
        for offset in stride(from: 0, to: blocks.count, by: 8) {
            let v0 = blocks.uint32BE(at: offset)
            let v1 = blocks.uint32BE(at: offset + 4)
            let r1 = decryptBlock(v0, v1, key: key3)
            let r2 = decryptBlock(r1.0, r1.1, key: key2)
            let r3 = decryptBlock(r2.0, r2.1, key: key1)
            blocks.setUInt32BE(r3.0, at: offset)
            blocks.setUInt32BE(r3.1, at: offset + 4)
        }
        return String(decoding: blocks.trimmedZeroSuffix(), as: UTF8.self)
    }
}

private final class StudentModXTEAIVCipher: StudentModXTEABase, StudentCipher {
    let algoID: String
    private let key1: [UInt32]
    private let key2: [UInt32]
    private let key3: [UInt32]
    private let iv: [UInt32]

    init(algoID: String, key1: [UInt32], key2: [UInt32], key3: [UInt32], iv: [UInt32]) {
        self.algoID = algoID
        self.key1 = key1
        self.key2 = key2
        self.key3 = key3
        self.iv = iv
    }

    func encrypt(_ text: String) throws -> String {
        var blocks = [UInt8](text.utf8).padded(toMultipleOf: 8)
        var previous = iv
        for offset in stride(from: 0, to: blocks.count, by: 8) {
            let v0 = blocks.uint32BE(at: offset) ^ previous[0]
            let v1 = blocks.uint32BE(at: offset + 4) ^ previous[1]
            let r1 = encryptBlock(v0, v1, key: key3)
            let r2 = encryptBlock(r1.0, r1.1, key: key2)
            let r3 = encryptBlock(r2.0, r2.1, key: key1)
            blocks.setUInt32BE(r3.0, at: offset)
            blocks.setUInt32BE(r3.1, at: offset + 4)
            previous = [r3.0, r3.1]
        }
        return blocks.hexUpper
    }

    func decrypt(_ hex: String) throws -> String {
        var blocks = try [UInt8](hexString: hex)
        var previous = iv
        for offset in stride(from: 0, to: blocks.count, by: 8) {
            let v0 = blocks.uint32BE(at: offset)
            let v1 = blocks.uint32BE(at: offset + 4)
            let r1 = decryptBlock(v0, v1, key: key1)
            let r2 = decryptBlock(r1.0, r1.1, key: key2)
            let r3 = decryptBlock(r2.0, r2.1, key: key3)
            blocks.setUInt32BE(r3.0 ^ previous[0], at: offset)
            blocks.setUInt32BE(r3.1 ^ previous[1], at: offset + 4)
            previous = [v0, v1]
        }
        return String(decoding: blocks.trimmedZeroSuffix(), as: UTF8.self)
    }
}

private enum Keys {
    static let aesCBCKey1: [UInt8] = [0x55, 0x48, 0x5B, 0x7A, 0x7C, 0x6D, 0x3E, 0x2A, 0x6C, 0x56, 0x4D, 0x2D, 0x22, 0x67, 0x56, 0x4D]
    static let aesCBCKey2: [UInt8] = [0x4E, 0x25, 0x53, 0x71, 0x5F, 0x7A, 0x5A, 0x5C, 0x60, 0x45, 0x63, 0x48, 0x66, 0x24, 0x65, 0x50]
    static let aesCBCIV: [UInt8] = [0x54, 0x67, 0x70, 0x75, 0x60, 0x73, 0x5A, 0x5C, 0x69, 0x40, 0x42, 0x66, 0x73, 0x5A, 0x7D, 0x5E]
    static let aesECBKey1: [UInt8] = [0x3A, 0x71, 0x7C, 0x4C, 0x51, 0x4F, 0x3C, 0x6A, 0x2E, 0x43, 0x7A, 0x43, 0x3B, 0x56, 0x57, 0x59]
    static let aesECBKey2: [UInt8] = [0x72, 0x6E, 0x25, 0x41, 0x45, 0x2F, 0x41, 0x54, 0x27, 0x4B, 0x3B, 0x3B, 0x59, 0x25, 0x52, 0x24]
    static let desCBCKey1: [UInt8] = [0x5E, 0x67, 0x72, 0x79, 0x28, 0x50, 0x47, 0x75, 0x6D, 0x48, 0x63, 0x74, 0x5D, 0x29, 0x21, 0x3C, 0x7E, 0x6B, 0x56, 0x29, 0x4F, 0x21, 0x52, 0x40]
    static let desCBCKey2: [UInt8] = [0x63, 0x73, 0x63, 0x26, 0x72, 0x5C, 0x5E, 0x73, 0x6B, 0x60, 0x74, 0x51, 0x7B, 0x74, 0x76, 0x7D, 0x3F, 0x59, 0x2E, 0x6D, 0x6F, 0x64, 0x3E, 0x69]
    static let desCBCIV: [UInt8] = [0x77, 0x2D, 0x56, 0x51, 0x28, 0x49, 0x7E, 0x57]
    static let desECBKey1: [UInt8] = [0x25, 0x6A, 0x63, 0x5A, 0x46, 0x3F, 0x26, 0x64, 0x53, 0x7A, 0x2E, 0x5B, 0x24, 0x4C, 0x62, 0x67, 0x2B, 0x2D, 0x67, 0x68, 0x43, 0x74, 0x69, 0x51]
    static let desECBKey2: [UInt8] = [0x59, 0x28, 0x5B, 0x7E, 0x7D, 0x26, 0x74, 0x49, 0x48, 0x76, 0x59, 0x58, 0x62, 0x75, 0x51, 0x55, 0x26, 0x73, 0x55, 0x5C, 0x67, 0x52, 0x2E, 0x6C]
    static let xteaKey1: [UInt32] = [0x7a7a676a, 0x277e4a73, 0x3e43296c, 0x577d7d7a]
    static let xteaKey2: [UInt32] = [0x3d3c695f, 0x71797a74, 0x445f5763, 0x6f692765]
    static let xteaKey3: [UInt32] = [0x5b5a683d, 0x2e572a77, 0x4a474465, 0x663d7e5c]
    static let xteaIVKey1: [UInt32] = [0x796d7855, 0x297b2355, 0x587d726e, 0x4d3d4423]
    static let xteaIVKey2: [UInt32] = [0x7c70525d, 0x5a585d3d, 0x413e4029, 0x28755d6a]
    static let xteaIVKey3: [UInt32] = [0x425e5f6e, 0x46754e24, 0x507b233d, 0x2d644641]
    static let xteaIV: [UInt32] = [0x544c2f3f, 0x6f485121]
}

private extension Array where Element == UInt8 {
    var hexUpper: String {
        map { String(format: "%02X", $0) }.joined()
    }

    init(hexString: String) throws {
        let cleaned = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleaned.count % 2 == 0 else {
            throw AppError.requestFailed("学生端：网关返回的加密数据不是有效 HEX")
        }
        var bytes: [UInt8] = []
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let next = cleaned.index(index, offsetBy: 2)
            guard let byte = UInt8(cleaned[index..<next], radix: 16) else {
                throw AppError.requestFailed("学生端：网关返回的加密数据不是有效 HEX")
            }
            bytes.append(byte)
            index = next
        }
        self = bytes
    }

    func padded(toMultipleOf blockSize: Int) -> [UInt8] {
        let padding = (blockSize - count % blockSize) % blockSize
        return padding == 0 ? self : self + [UInt8](repeating: 0, count: padding)
    }

    func trimmedZeroSuffix() -> [UInt8] {
        var result = self
        while result.last == 0 {
            result.removeLast()
        }
        return result
    }

    func uint32BE(at offset: Int) -> UInt32 {
        (UInt32(self[offset]) << 24)
            | (UInt32(self[offset + 1]) << 16)
            | (UInt32(self[offset + 2]) << 8)
            | UInt32(self[offset + 3])
    }

    mutating func setUInt32BE(_ value: UInt32, at offset: Int) {
        self[offset] = UInt8((value >> 24) & 0xFF)
        self[offset + 1] = UInt8((value >> 16) & 0xFF)
        self[offset + 2] = UInt8((value >> 8) & 0xFF)
        self[offset + 3] = UInt8(value & 0xFF)
    }
}

private extension String.Encoding {
    static let gb18030Student = String.Encoding(
        rawValue: CFStringConvertEncodingToNSStringEncoding(
            CFStringEncoding(CFStringEncodings.GB_18030_2000.rawValue)
        )
    )
}
