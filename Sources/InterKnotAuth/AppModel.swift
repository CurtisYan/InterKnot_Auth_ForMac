import AppKit
import Combine
import Foundation
import ServiceManagement
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    private static let maxLogEntries = 400
    private static let logTrimThreshold = 500

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
    private let studentDialer = StudentDialerService()
    private let probeService = ConnectivityProbeService()
    private let easyTier = EasyTierService()
    private let webUI = LocalWebServer()
    private var watchdog: WatchdogService?
    private var loginTask: Task<Void, Never>?
    private var captchaContinuation: CheckedContinuation<String?, Never>?
    private var lastSignature: String = ""
    private var cancellables = Set<AnyCancellable>()
    private var loginGeneration = 0
    private var probeGeneration = 0
    private var isLogoutInProgress = false
    private var isApplyingLaunchAtLogin = false
    private var retryFailedLoginWithWatchdog = false
    private var lastSessionUsername = ""

    init() {
        var loaded = configStore.load()
        loaded.username = loaded.username.sanitizedAccountIdentifier
        loaded.accountHistory = Self.normalizedAccountHistory(loaded.accountHistory)
        settings = loaded
        log("欢迎使用 InterKnot for macOS")
        log("配置已加载")
        bindAutoSave()
        reconcileLaunchAtLogin()

        if loaded.autoShare {
            startEasyTierServer()
        }
        if loaded.autoConnect, loaded.savePassword, !loaded.username.isEmpty {
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 600_000_000)
                login()
            }
        }
    }

    func saveSettings() {
        persistSettings(settings)
        log("配置已保存")
    }

    func reloadPassword() {
        password = credentialStore.password(for: settings.username, allowUserPrompt: true) ?? ""
    }

    func selectAccount(_ account: String) {
        settings.username = account.sanitizedAccountIdentifier
        password = ""
    }

    func removeAccountFromHistory(_ account: String) {
        let sanitized = account.sanitizedAccountIdentifier
        guard !sanitized.isEmpty else { return }
        settings.accountHistory.removeAll { $0 == sanitized }
        credentialStore.delete(account: sanitized)
        if settings.username == sanitized {
            settings.username = settings.accountHistory.first ?? ""
            password = ""
        }
        log("已删除账号历史：\(sanitized)")
    }

    func login(account: MultiLoginAccount? = nil, force: Bool = false) {
        guard !isLogoutInProgress else {
            log("正在注销，已忽略登录请求")
            return
        }
        if case .loggingIn = connectionState, !force {
            log("正在登录，已忽略重复登录请求")
            return
        }
        if case .loggingIn = connectionState, force {
            log("强制重连：取消当前认证请求")
        }
        loginTask?.cancel()
        cancelPendingCaptcha()
        studentDialer.stopHeartbeat()
        loginGeneration += 1
        let generation = loginGeneration

        let username = account?.username.isEmpty == false ? account!.username : settings.username
        let userIP = account?.userIP.isEmpty == false ? account!.userIP : settings.wlanUserIP
        if account == nil,
           password.isEmpty,
           settings.savePassword,
           let savedPassword = credentialStore.password(for: username, allowUserPrompt: true) {
            password = savedPassword
        }
        let request = LoginRequest(
            username: username,
            password: password,
            userIP: userIP,
            mode: settings.loginMode
        )

        let willUseStudentDialer = shouldUseStudentDialer(for: request)
        let shouldRefreshUserIP = account == nil && settings.autoUpdateUserIP && !willUseStudentDialer
        let wasWatchdogRunning = watchdog != nil
        retryFailedLoginWithWatchdog = false
        stopWatchdog()
        guard validateBeforeLogin(request: request, allowRefreshParameters: shouldRefreshUserIP || willUseStudentDialer) else {
            return
        }

        connectionState = .loggingIn
        logLoginRoute(request, usesStudentDialer: willUseStudentDialer)
        log("开始认证：\(request.username)，IP：\(request.userIP)")

        loginTask = Task { [weak self] in
            guard let self else { return }
            do {
                let preparedRequest = try await self.prepareLoginRequest(request, refreshUserIP: shouldRefreshUserIP)
                let result: LoginResult
                let effectiveRequest: LoginRequest
                if self.shouldUseStudentDialer(for: preparedRequest) {
                    let studentResult = try await studentDialer.login(
                        request: preparedRequest,
                        logger: { [weak self] message in
                            Task { @MainActor in
                                guard let self, self.isCurrentLogin(generation) else { return }
                                self.log(message)
                            }
                        }
                    )
                    var updatedRequest = preparedRequest
                    updatedRequest.userIP = studentResult.userIP
                    await MainActor.run {
                        if !studentResult.userIP.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                           studentResult.userIP != "0.0.0.0" {
                            self.settings.wlanUserIP = studentResult.userIP
                        }
                        if !studentResult.acIP.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                           studentResult.acIP != "0.0.0.0" {
                            self.settings.wlanACIP = studentResult.acIP
                        }
                    }
                    result = studentResult.result
                    effectiveRequest = updatedRequest
                } else {
                    result = try await authenticator.login(
                        request: preparedRequest,
                        settings: settings,
                        captchaProvider: { [weak self] imageData, suggestedCode in
                            await self?.requestCaptcha(
                                imageData: imageData,
                                title: "输入登录验证码",
                                submitTitle: "继续登录",
                                generation: generation,
                                suggestedCode: suggestedCode
                            )
                        },
                        logger: { [weak self] message in
                            Task { @MainActor in
                                guard let self, self.isCurrentLogin(generation) else { return }
                                self.log(message)
                            }
                        }
                    )
                    effectiveRequest = preparedRequest
                }

                await MainActor.run {
                    guard self.isCurrentLogin(generation) else { return }
                    if result.success {
                        self.connectionState = .connected(result.message)
                        if let signature = result.signature, !signature.isEmpty {
                            self.lastSignature = signature
                            self.lastSessionUsername = effectiveRequest.username
                        } else if self.lastSessionUsername == effectiveRequest.username {
                            self.lastSignature = ""
                            self.lastSessionUsername = ""
                        }
                        if self.settings.savePassword {
                            self.credentialStore.save(password: self.password, for: effectiveRequest.username)
                        } else {
                            self.credentialStore.delete(account: effectiveRequest.username)
                        }
                        self.settings.username = effectiveRequest.username
                        self.rememberAccount(effectiveRequest.username)
                        self.configStore.save(self.settings)
                        self.log(result.message)
                        self.startWatchdogIfNeeded()
                        self.scheduleConnectivityCheck(generation: generation)
                    } else {
                        self.fail(result.message)
                        self.restoreWatchdogAfterLoginFailure(wasRunning: wasWatchdogRunning)
                    }
                }
            } catch is CancellationError {
                await MainActor.run {
                    guard self.isCurrentLogin(generation) else { return }
                    self.log("登录已取消")
                }
            } catch {
                await MainActor.run {
                    guard self.isCurrentLogin(generation) else { return }
                    self.fail(error.localizedDescription)
                    let shouldRetry = self.isRetryableLoginTransportError(error)
                    self.restoreWatchdogAfterLoginFailure(wasRunning: wasWatchdogRunning, retryLogin: shouldRetry)
                }
            }
        }
    }

    func logout() {
        isLogoutInProgress = true
        loginGeneration += 1
        probeGeneration += 1
        loginTask?.cancel()
        cancelPendingCaptcha()
        isProbing = false
        retryFailedLoginWithWatchdog = false
        stopWatchdog()
        let requestedUsername = settings.username
        let sessionSignature = requestedUsername == lastSessionUsername ? lastSignature : ""
        guard !sessionSignature.isEmpty else {
            connectionState = .loggingOut
            log("开始注销")
            Task {
                if shouldUseStudentDialerForCurrentAccount() {
                    await MainActor.run {
                        self.connectionState = .idle
                        self.isLogoutInProgress = false
                        self.lastSignature = ""
                        self.lastSessionUsername = ""
                        self.log("当前在线会话不是本程序建立的学生端会话，缺少 term-url，无法主动通知网关下线；请使用天翼校园网手动下线或等待会话过期", level: "ERROR")
                    }
                } else {
                    await MainActor.run {
                        self.connectionState = .idle
                        self.isLogoutInProgress = false
                        self.log("本地没有网页登录 signature，无法主动通知网关下线；请先重新登录或等待网关会话过期", level: "ERROR")
                    }
                }
            }
            return
        }

        connectionState = .loggingOut
        log("开始注销")
        Task {
            do {
                if sessionSignature == StudentDialerService.signatureMarker {
                    let message = try await studentDialer.logout { [weak self] logMessage in
                        Task { @MainActor in self?.log(logMessage) }
                    }
                    await MainActor.run {
                        self.connectionState = .idle
                        self.lastSignature = ""
                        self.lastSessionUsername = ""
                        self.isLogoutInProgress = false
                        self.log(message)
                    }
                    return
                }
                await MainActor.run {
                    self.log("发送下线请求：\(self.resolvedUserIP())")
                }
                let message = try await authenticator.logout(
                    settings: settings,
                    userIP: resolvedUserIP(),
                    account: lastSessionUsername,
                    signature: sessionSignature
                )
                await MainActor.run {
                    self.connectionState = .idle
                    self.lastSignature = ""
                    self.lastSessionUsername = ""
                    self.isLogoutInProgress = false
                    self.log("成功发送下线请求")
                    self.log(message)
                }
            } catch {
                await MainActor.run {
                    self.isLogoutInProgress = false
                    self.fail("下线失败：\(error.localizedDescription)")
                }
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
        log("尝试自动获取认证参数")
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
                    self.log("请关闭代理，并开启浏览器无痕模式访问 2.2.2.2；如果能跳转，把完整地址复制到账号页手动解析", level: "INFO")
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

    func syncLaunchAtLoginStatus() {
        settings.launchAtLogin = isLaunchAtLoginEnabled()
    }

    func checkConnectivity() {
        guard !isProbing else { return }
        guard !isLogoutInProgress, connectionState != .loggingOut else { return }
        isProbing = true
        probeGeneration += 1
        let generation = probeGeneration
        log("开始访问目标检测")
        Task { [weak self] in
            guard let self else { return }
            let results = await probeService.measure(urlStrings: settings.probeURLs)
            await MainActor.run {
                guard generation == self.probeGeneration,
                      !self.isLogoutInProgress,
                      self.connectionState != .loggingOut else {
                    self.isProbing = false
                    return
                }
                self.probeResults = results
                self.isProbing = false
                if let fastest = results.filter(\.success).compactMap(\.latencyMS).min() {
                    self.log("访问检测完成，最快 \(fastest) ms")
                } else {
                    self.log("外网访问检测失败：所有检测点不可达，认证已成功但网络可能尚未放行或检测点被拦截", level: "ERROR")
                }
            }
        }
    }

    func startWatchdogIfNeeded() {
        guard settings.enableWatchdog else { return }
        watchdog?.stop()
        let service = WatchdogService(
            probeURLs: settings.probeURLs,
            hasLocalIP: { NetworkInterfaceService.localIPv4Address() != nil },
            shouldReconnect: { [weak self] in
                await MainActor.run {
                    guard let self, !self.isLogoutInProgress, self.connectionState != .loggingOut else {
                        return false
                    }
                    return self.retryFailedLoginWithWatchdog
                }
            },
            reconnect: { [weak self] in
                Task { @MainActor in
                    guard let self, !self.isLogoutInProgress, self.connectionState != .loggingOut else { return }
                    self.log("看门狗触发重连")
                    self.login(force: true)
                }
            },
            logger: { [weak self] message in
                Task { @MainActor in
                    guard let self, !self.isLogoutInProgress, self.connectionState != .loggingOut else { return }
                    self.log(message)
                }
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
        if logs.count > Self.logTrimThreshold {
            logs.removeFirst(logs.count - Self.maxLogEntries)
        }
        Logger.write("[\(level)] \(message)")
    }

    private func bindAutoSave() {
        $settings
            .dropFirst()
            .removeDuplicates()
            .debounce(for: .milliseconds(600), scheduler: RunLoop.main)
            .sink { [weak self] settings in
                Task { @MainActor in
                    self?.persistSettings(settings)
                }
            }
            .store(in: &cancellables)

        $settings
            .map(\.launchAtLogin)
            .removeDuplicates()
            .dropFirst()
            .sink { [weak self] enabled in
                Task { @MainActor in
                    self?.applyLaunchAtLogin(enabled)
                }
            }
            .store(in: &cancellables)

    }

    private func persistSettings(_ settings: AppSettings) {
        configStore.save(settings)
    }

    private func rememberAccount(_ account: String) {
        let sanitized = account.sanitizedAccountIdentifier
        guard !sanitized.isEmpty else { return }
        settings.accountHistory.removeAll { $0 == sanitized }
        settings.accountHistory.insert(sanitized, at: 0)
        if settings.accountHistory.count > 12 {
            settings.accountHistory.removeLast(settings.accountHistory.count - 12)
        }
    }

    private static func normalizedAccountHistory(_ history: [String]) -> [String] {
        var result: [String] = []
        for account in history {
            let sanitized = account.sanitizedAccountIdentifier
            guard !sanitized.isEmpty, !result.contains(sanitized) else { continue }
            result.append(sanitized)
            if result.count == 12 { break }
        }
        return result
    }

    private func scheduleConnectivityCheck(generation: Int) {
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            guard self.isCurrentLogin(generation) else { return }
            self.checkConnectivity()
        }
    }

    private func reconcileLaunchAtLogin() {
        applyLaunchAtLogin(settings.launchAtLogin, quiet: true)
    }

    private func isLaunchAtLoginEnabled() -> Bool {
        SMAppService.mainApp.status == .enabled
    }

    private func applyLaunchAtLogin(_ enabled: Bool, quiet: Bool = false) {
        guard !isApplyingLaunchAtLogin else { return }
        isApplyingLaunchAtLogin = true
        defer { isApplyingLaunchAtLogin = false }

        do {
            if enabled {
                if SMAppService.mainApp.status != .enabled {
                    try SMAppService.mainApp.register()
                }
                if !quiet {
                    log("开机自动启动已开启")
                }
            } else {
                if SMAppService.mainApp.status == .enabled {
                    try SMAppService.mainApp.unregister()
                }
                if !quiet {
                    log("开机自动启动已关闭")
                }
            }
        } catch {
            log("设置开机自动启动失败：\(error.localizedDescription)", level: "ERROR")
            settings.launchAtLogin = isLaunchAtLoginEnabled()
        }
    }

    private func resolvedUserIP() -> String {
        if !settings.wlanUserIP.isEmpty, settings.wlanUserIP != "0.0.0.0" {
            return settings.wlanUserIP
        }
        return NetworkInterfaceService.localIPv4Address() ?? "0.0.0.0"
    }

    private func validateBeforeLogin(request: LoginRequest, allowRefreshParameters: Bool = false) -> Bool {
        var missing: Set<RequiredField> = []
        if request.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            missing.insert(.username)
        }
        if request.username != request.username.sanitizedAccountIdentifier {
            missing.insert(.username)
        }
        if request.password.isEmpty {
            missing.insert(.password)
        }
        if !allowRefreshParameters, settings.esurfingURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            missing.insert(.esurfingURL)
        }
        if !allowRefreshParameters,
           settings.wlanACIP.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || settings.wlanACIP == "0.0.0.0" {
            missing.insert(.wlanACIP)
        }
        if !allowRefreshParameters && !isUsableLoginIP(request.userIP) {
            missing.insert(.wlanUserIP)
        }

        missingFields = missing
        if missing.contains(.username), request.username != request.username.sanitizedAccountIdentifier {
            validationMessage = "账号只能输入一行英文字母或数字，不能包含空格或符号"
        } else {
            validationMessage = missing.isEmpty ? "" : "请补全：\(missing.map(\.title).sorted().joined(separator: "、"))"
        }
        guard missing.isEmpty else {
            if missing.contains(.username) || missing.contains(.password) {
                selectedSection = .accounts
            } else {
                selectedSection = .accounts
            }
            fail(validationMessage)
            return false
        }
        return true
    }

    private func prepareLoginRequest(_ request: LoginRequest, refreshUserIP: Bool) async throws -> LoginRequest {
        guard refreshUserIP else { return request }

        log("自动更新认证 IP：尝试从校园网重定向获取")
        var prepared = request
        do {
            let params = try await authenticator.detectParameters()
            settings.wlanACIP = params.wlanACIP
            settings.wlanUserIP = params.wlanUserIP
            missingFields.subtract([.wlanACIP, .wlanUserIP])
            prepared.userIP = params.wlanUserIP
            log("自动更新认证 IP 成功：\(params.wlanUserIP)，保留认证网关：\(settings.esurfingURL)")
        } catch {
            log("自动更新认证 IP 失败：\(error.localizedDescription)，继续使用当前配置", level: "ERROR")
        }

        guard !settings.esurfingURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !settings.wlanACIP.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              settings.wlanACIP != "0.0.0.0",
              isUsableLoginIP(prepared.userIP) else {
            throw AppError.requestFailed("自动更新认证参数失败，且当前认证参数不完整")
        }
        return prepared
    }

    private func isUsableLoginIP(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty && trimmed != "0.0.0.0"
    }

    private func shouldUseStudentDialer(for request: LoginRequest) -> Bool {
        request.mode == .automatic && !request.username.lowercased().hasPrefix("t")
    }

    private func shouldUseStudentDialerForCurrentAccount() -> Bool {
        settings.loginMode == .automatic && !settings.username.lowercased().hasPrefix("t")
    }

    private func logLoginRoute(_ request: LoginRequest, usesStudentDialer: Bool) {
        if usesStudentDialer {
            log("登录路由：学生客户端协议")
        } else if request.mode == .teacher {
            log("登录路由：教师/t 网页认证（当前登录模式强制）")
        } else {
            log("登录路由：教师/t 网页认证（账号以 t 开头）")
        }
    }

    private func isCurrentLogin(_ generation: Int) -> Bool {
        generation == loginGeneration && !isLogoutInProgress && connectionState != .loggingOut
    }

    private func cancelPendingCaptcha() {
        captchaContinuation?.resume(returning: nil)
        captchaContinuation = nil
        captchaChallenge = nil
        captchaInput = ""
    }

    private func requestCaptcha(
        imageData: Data,
        title: String,
        submitTitle: String,
        generation: Int? = nil,
        suggestedCode: String? = nil
    ) async -> String? {
        if let generation, !isCurrentLogin(generation) {
            return nil
        }
        guard !isLogoutInProgress, connectionState != .loggingOut else {
            return nil
        }
        return await withCheckedContinuation { continuation in
            captchaContinuation = continuation
            captchaTitle = title
            captchaSubmitTitle = submitTitle
            captchaChallenge = CaptchaChallenge(imageData: imageData)
            captchaInput = suggestedCode ?? ""
        }
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
                captchaProvider: { [weak self] imageData, suggestedCode in
                    await self?.requestCaptcha(
                        imageData: imageData,
                        title: "输入多拨验证码",
                        submitTitle: "继续多拨",
                        suggestedCode: suggestedCode
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
            try webUI.start(
                port: 50000,
                htmlProvider: { [weak self] in
                    self?.currentStatusHTML() ?? ""
                },
                downloadEnabledProvider: { [weak self] in
                    self?.settings.easyTier.enableWebDownload ?? false
                }
            )
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

    private func restoreWatchdogAfterLoginFailure(wasRunning: Bool, retryLogin: Bool = false) {
        guard settings.enableWatchdog, wasRunning || retryLogin else { return }
        retryFailedLoginWithWatchdog = retryLogin
        if retryLogin {
            log("认证请求失败，将由看门狗继续重试")
        }
        startWatchdogIfNeeded()
    }

    private func isRetryableLoginTransportError(_ error: Error) -> Bool {
        let nsError = error as NSError
        guard nsError.domain == NSURLErrorDomain else {
            return false
        }
        let code = URLError.Code(rawValue: nsError.code)

        switch code {
        case .notConnectedToInternet,
             .networkConnectionLost,
             .timedOut,
             .cannotFindHost,
             .cannotConnectToHost,
             .dnsLookupFailed,
             .secureConnectionFailed,
             .cannotLoadFromNetwork:
            return true
        default:
            return false
        }
    }
}
