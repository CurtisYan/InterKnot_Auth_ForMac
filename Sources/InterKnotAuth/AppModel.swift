import AppKit
import Foundation
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    @Published var settings: AppSettings
    @Published var password: String = ""
    @Published var selectedSection: AppSection = .dashboard
    @Published var connectionState: ConnectionState = .idle
    @Published var logs: [LogEntry] = []
    @Published var captchaChallenge: CaptchaChallenge?
    @Published var captchaInput: String = ""
    @Published var captchaTitle: String = "输入验证码"
    @Published var captchaSubmitTitle: String = "继续登录"
    @Published var easyTierState: String = "未启动"
    @Published var webUIState: String = "未启动"
    @Published var watchdogState: String = "未启动"
    @Published var missingFields: Set<RequiredField> = []
    @Published var validationMessage: String = ""
    @Published var showLogConsole: Bool = true
    @Published var isProbing: Bool = false
    @Published var probeResults: [ProbeResult] = []
    @Published var redirectURLInput: String = ""
    @Published var showManualParseSheet: Bool = false

    private let configStore = ConfigStore()
    private let credentialStore = CredentialStore()
    private let authenticator = AuthenticationService()
    private let probeService = ConnectivityProbeService()
    private let easyTier = EasyTierService()
    private let webUI = LocalWebServer()
    private var watchdog: WatchdogService?
    private var loginTask: Task<Void, Never>?
    private var captchaContinuation: CheckedContinuation<String?, Never>?
    private var lastSignature: String = ""

    init() {
        let loaded = configStore.load()
        settings = loaded
        password = credentialStore.password(for: loaded.username) ?? ""
        log("欢迎使用 InterKnot for macOS")
        log("配置已加载")

        if loaded.autoShare {
            startEasyTierServer()
        }
        if loaded.autoConnect, loaded.savePassword, !loaded.username.isEmpty, !password.isEmpty {
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 600_000_000)
                login()
            }
        }
    }

    func saveSettings() {
        configStore.save(settings)
        if settings.savePassword, !settings.username.isEmpty, !password.isEmpty {
            credentialStore.save(password: password, for: settings.username)
        }
        log("配置已保存")
    }

    func reloadPassword() {
        password = credentialStore.password(for: settings.username) ?? ""
    }

    func login(account: MultiLoginAccount? = nil) {
        loginTask?.cancel()

        let username = account?.username.isEmpty == false ? account!.username : settings.username
        let userIP = account?.userIP.isEmpty == false ? account!.userIP : settings.wlanUserIP
        let request = LoginRequest(
            username: username,
            password: password,
            userIP: userIP,
            mode: settings.loginMode
        )

        guard validateBeforeLogin(request: request) else {
            return
        }

        connectionState = .loggingIn
        log("开始认证：\(request.username)，IP：\(request.userIP)")

        loginTask = Task { [weak self] in
            guard let self else { return }
            do {
                let result = try await authenticator.login(
                    request: request,
                    settings: settings,
                    captchaProvider: { [weak self] imageData in
                        await self?.requestCaptcha(
                            imageData: imageData,
                            title: "输入登录验证码",
                            submitTitle: "继续登录"
                        )
                    },
                    logger: { [weak self] message in
                        Task { @MainActor in self?.log(message) }
                    }
                )

                await MainActor.run {
                    if result.success {
                        self.connectionState = .connected(result.message)
                        self.lastSignature = result.signature ?? ""
                        if self.settings.savePassword {
                            self.credentialStore.save(password: self.password, for: request.username)
                        }
                        self.settings.username = request.username
                        self.configStore.save(self.settings)
                        self.log("登录成功")
                        self.startWatchdogIfNeeded()
                        self.checkConnectivity()
                    } else {
                        self.fail(result.message)
                    }
                }
            } catch is CancellationError {
                await MainActor.run { self.log("登录已取消") }
            } catch {
                await MainActor.run { self.fail(error.localizedDescription) }
            }
        }
    }

    func logout() {
        loginTask?.cancel()
        Task {
            do {
                let signature = try await signatureForLogout()
                try await authenticator.logout(
                    settings: settings,
                    userIP: resolvedUserIP(),
                    account: settings.username,
                    signature: signature
                )
                await MainActor.run {
                    self.stopWatchdog()
                    self.connectionState = .idle
                    self.lastSignature = ""
                    self.log("注销成功")
                }
            } catch {
                await MainActor.run { self.fail("下线失败：\(error.localizedDescription)") }
            }
        }
    }

    func runMultiLogin() {
        let accounts = settings.multiAccounts.filter { $0.enabled && !$0.username.isEmpty }
        guard !accounts.isEmpty else {
            fail("没有可用的多拨账号")
            return
        }

        log("开始多拨，共 \(accounts.count) 个账号")
        Task { [weak self] in
            guard let self else { return }
            for account in accounts {
                let request = LoginRequest(
                    username: account.username,
                    password: account.password.isEmpty ? self.password : account.password,
                    userIP: account.userIP.isEmpty ? self.resolvedUserIP() : account.userIP,
                    mode: self.settings.loginMode
                )
                await self.runSingleMultiLogin(request: request, label: account.label)
            }
            await MainActor.run {
                self.log("多拨流程结束")
                self.startWatchdogIfNeeded()
            }
        }
    }

    func detectCampusParameters() {
        log("尝试从广东天翼重定向自动获取认证参数")
        Task { [weak self] in
            guard let self else { return }
            do {
                let params = try await authenticator.detectParameters()
                await MainActor.run {
                    self.settings.esurfingURL = params.esurfingURL
                    self.settings.wlanACIP = params.wlanACIP
                    self.settings.wlanUserIP = params.wlanUserIP
                    self.missingFields.subtract([.esurfingURL, .wlanACIP, .wlanUserIP])
                    self.log("自动获取成功：\(params.esurfingURL), \(params.wlanACIP), \(params.wlanUserIP)")
                }
            } catch {
                await MainActor.run {
                    self.fail("自动获取认证参数失败：\(error.localizedDescription)")
                    self.log("请连接校园网络并关闭代理；然后在浏览器访问 2.2.2.2，将跳转后的完整地址复制到认证参数页解析", level: "INFO")
                }
            }
        }
    }

    func parseRedirectURLInput() {
        do {
            let params = try authenticator.parseParameters(from: redirectURLInput)
            settings.esurfingURL = params.esurfingURL
            settings.wlanACIP = params.wlanACIP
            settings.wlanUserIP = params.wlanUserIP
            missingFields.subtract([.esurfingURL, .wlanACIP, .wlanUserIP])
            validationMessage = ""
            showManualParseSheet = false
            log("已解析跳转地址：\(params.esurfingURL), \(params.wlanACIP), \(params.wlanUserIP)")
        } catch {
            fail("解析跳转地址失败：\(error.localizedDescription)")
        }
    }

    func restoreDefaultRSAPublicKey() {
        settings.rsaPublicKey = AppSettings.defaultRSAPublicKey
        log("已恢复默认 RSA 公钥")
    }

    func checkConnectivity() {
        guard !isProbing else { return }
        isProbing = true
        log("开始访问目标检测")
        Task { [weak self] in
            guard let self else { return }
            let results = await probeService.measure(urlStrings: settings.probeURLs)
            await MainActor.run {
                self.probeResults = results
                self.isProbing = false
                if let fastest = results.filter(\.success).compactMap(\.latencyMS).min() {
                    self.log("访问检测完成，最快 \(fastest) ms")
                } else {
                    self.log("访问检测失败：所有目标不可达", level: "ERROR")
                }
            }
        }
    }

    func startWatchdogIfNeeded() {
        guard settings.enableWatchdog else { return }
        watchdog?.stop()
        let service = WatchdogService(
            timeout: settings.watchdogTimeout,
            probeURLs: settings.probeURLs,
            hasLocalIP: { NetworkInterfaceService.localIPv4Address() != nil },
            reconnect: { [weak self] in
                Task { @MainActor in
                    self?.log("看门狗触发重连")
                    self?.login()
                }
            },
            logger: { [weak self] message in
                Task { @MainActor in self?.log(message) }
            }
        )
        watchdog = service
        service.start()
        watchdogState = "运行中"
        log("看门狗已启动")
    }

    func stopWatchdog() {
        watchdog?.stop()
        watchdog = nil
        watchdogState = "未启动"
        log("看门狗已停止")
    }

    func startEasyTierServer() {
        do {
            try easyTier.startServer(settings: settings.easyTier) { [weak self] message in
                Task { @MainActor in self?.log("ET：\(message)") }
            }
            easyTierState = "共享中"
            startWebUI()
        } catch {
            fail("启动共享失败：\(error.localizedDescription)")
        }
    }

    func startEasyTierClient() {
        do {
            try easyTier.startClient(settings: settings.easyTier) { [weak self] message in
                Task { @MainActor in self?.log("ET：\(message)") }
            }
            easyTierState = "已连接"
            startWebUI()
        } catch {
            fail("连接隧道失败：\(error.localizedDescription)")
        }
    }

    func stopEasyTier() {
        easyTier.stop()
        webUI.stop()
        easyTierState = "未启动"
        webUIState = "未启动"
        log("EasyTier 和 WebUI 已停止")
    }

    func submitCaptcha() {
        let code = captchaInput.trimmingCharacters(in: .whitespacesAndNewlines)
        captchaContinuation?.resume(returning: code.isEmpty ? nil : code)
        captchaContinuation = nil
        captchaChallenge = nil
        captchaInput = ""
    }

    func cancelCaptcha() {
        captchaContinuation?.resume(returning: nil)
        captchaContinuation = nil
        captchaChallenge = nil
        captchaInput = ""
    }

    func log(_ message: String, level: String = "INFO") {
        logs.append(LogEntry(level: level, message: message))
        if logs.count > 1000 {
            logs.removeFirst(logs.count - 1000)
        }
        Logger.write("[\(level)] \(message)")
    }

    private func resolvedUserIP() -> String {
        if !settings.wlanUserIP.isEmpty, settings.wlanUserIP != "0.0.0.0" {
            return settings.wlanUserIP
        }
        return NetworkInterfaceService.localIPv4Address() ?? "0.0.0.0"
    }

    private func validateBeforeLogin(request: LoginRequest) -> Bool {
        var missing: Set<RequiredField> = []
        if request.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            missing.insert(.username)
        }
        if request.password.isEmpty {
            missing.insert(.password)
        }
        if settings.esurfingURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            missing.insert(.esurfingURL)
        }
        if settings.wlanACIP.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || settings.wlanACIP == "0.0.0.0" {
            missing.insert(.wlanACIP)
        }
        if request.userIP.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || request.userIP == "0.0.0.0" {
            missing.insert(.wlanUserIP)
        }

        missingFields = missing
        validationMessage = missing.isEmpty ? "" : "请补全：\(missing.map(\.title).sorted().joined(separator: "、"))"
        guard missing.isEmpty else {
            if missing.contains(.username) || missing.contains(.password) {
                selectedSection = .accounts
            } else {
                selectedSection = .network
            }
            fail(validationMessage)
            return false
        }
        return true
    }

    private func requestCaptcha(imageData: Data, title: String, submitTitle: String) async -> String? {
        await withCheckedContinuation { continuation in
            captchaContinuation = continuation
            captchaTitle = title
            captchaSubmitTitle = submitTitle
            captchaChallenge = CaptchaChallenge(imageData: imageData)
            captchaInput = ""
        }
    }

    private func signatureForLogout() async throws -> String {
        if !lastSignature.isEmpty {
            log("开始注销")
            return lastSignature
        }

        let request = LoginRequest(
            username: settings.username,
            password: password,
            userIP: settings.wlanUserIP,
            mode: settings.loginMode
        )
        guard validateBeforeLogin(request: request) else {
            throw AppError.requestFailed(validationMessage)
        }

        await MainActor.run {
            self.connectionState = .loggingIn
            self.log("注销前需要获取下线签名")
        }

        let result = try await authenticator.login(
            request: request,
            settings: settings,
            captchaProvider: { [weak self] imageData in
                await self?.requestCaptcha(
                    imageData: imageData,
                    title: "输入注销验证码",
                    submitTitle: "继续注销"
                )
            },
            logger: { [weak self] message in
                Task { @MainActor in self?.log("注销准备：\(message)") }
            }
        )

        guard result.success else {
            throw AppError.requestFailed(result.message)
        }
        guard let signature = result.signature, !signature.isEmpty else {
            throw AppError.requestFailed("未获取到下线签名")
        }
        await MainActor.run {
            self.lastSignature = signature
            self.log("已获取下线签名")
        }
        return signature
    }

    private func runSingleMultiLogin(request: LoginRequest, label: String) async {
        let lineName = label.isEmpty ? request.userIP : label
        await MainActor.run {
            self.log("多拨线路 \(lineName)：开始登录")
        }

        do {
            let result = try await authenticator.login(
                request: request,
                settings: settings,
                captchaProvider: { [weak self] imageData in
                    await self?.requestCaptcha(
                        imageData: imageData,
                        title: "输入多拨验证码",
                        submitTitle: "继续多拨"
                    )
                },
                logger: { [weak self] message in
                    Task { @MainActor in self?.log("多拨 \(lineName)：\(message)") }
                }
            )
            await MainActor.run {
                if result.success {
                    self.log("多拨线路 \(lineName)：登录成功")
                } else {
                    self.log("多拨线路 \(lineName)：\(result.message)", level: "ERROR")
                }
            }
        } catch {
            await MainActor.run {
                self.log("多拨线路 \(lineName)：\(error.localizedDescription)", level: "ERROR")
            }
        }
    }

    private func startWebUI() {
        do {
            try webUI.start(port: 50000) { [weak self] in
                self?.currentStatusHTML() ?? ""
            }
            webUIState = "http://localhost:50000"
            log("WebUI 已启动：http://localhost:50000")
        } catch {
            fail("WebUI 启动失败：\(error.localizedDescription)")
        }
    }

    private func currentStatusHTML() -> String {
        """
        <!doctype html>
        <html lang="zh-CN">
        <head><meta charset="utf-8"><title>InterKnot</title></head>
        <body style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:32px">
        <h1>InterKnot for macOS</h1>
        <p>认证状态：\(connectionState.title)</p>
        <p>EasyTier：\(easyTierState)</p>
        <p>WebUI：\(webUIState)</p>
        </body>
        </html>
        """
    }

    private func fail(_ message: String) {
        connectionState = .failed(message)
        log(message, level: "ERROR")
    }
}
