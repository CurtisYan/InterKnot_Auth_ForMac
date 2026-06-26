import AppKit
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationView {
            SidebarView()
            DetailView()
        }
        .sheet(item: $model.captchaChallenge) { challenge in
            CaptchaSheet(challenge: challenge)
                .environmentObject(model)
        }
        .sheet(isPresented: $model.showManualParseSheet) {
            ManualParseSheet()
                .environmentObject(model)
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button {
                    NSApp.keyWindow?.firstResponder?.tryToPerform(
                        #selector(NSSplitViewController.toggleSidebar(_:)),
                        with: nil
                    )
                } label: {
                    Label("侧边栏", systemImage: "sidebar.leading")
                }
                .help("折叠或展开侧边栏")
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    model.showLogConsole.toggle()
                } label: {
                    Label("日志", systemImage: model.showLogConsole ? "terminal.fill" : "terminal")
                }
                .help(model.showLogConsole ? "收起日志" : "显示日志")
            }
        }
    }
}

private struct SidebarView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        List(selection: $model.selectedSection) {
            ForEach(AppSection.allCases) { section in
                Label(section.rawValue, systemImage: icon(for: section))
                    .tag(section)
            }
        }
        .listStyle(.sidebar)
        .frame(minWidth: 190, idealWidth: 220, maxWidth: 280)
    }

    private func icon(for section: AppSection) -> String {
        switch section {
        case .dashboard: return "gauge.with.dots.needle.67percent"
        case .accounts: return "person.crop.circle"
        case .network: return "network"
        case .multiLogin: return "square.stack.3d.up"
        case .tunnel: return "point.3.connected.trianglepath.dotted"
        case .settings: return "gearshape"
        }
    }
}

private struct DetailView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Group {
            if model.showLogConsole {
                VSplitView {
                    MainDetailContent()
                        .frame(minHeight: 360)
                    GlobalLogConsole()
                        .frame(minHeight: 140, idealHeight: 220)
                }
            } else {
                MainDetailContent()
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

private struct MainDetailContent: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            HeaderView()
            Divider()
            Group {
                switch model.selectedSection {
                case .dashboard:
                    DashboardView()
                case .accounts:
                    AccountView()
                case .network:
                    NetworkSettingsView()
                case .multiLogin:
                    MultiLoginView()
                case .tunnel:
                    TunnelView()
                case .settings:
                    SettingsView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

private struct HeaderView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        HStack(spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("InterKnot")
                    .font(.system(size: 24, weight: .semibold))
                Text("绳网认证 for macOS")
                    .foregroundStyle(.secondary)
            }

            Spacer()

            StatusPill(title: model.connectionState.title, detail: model.connectionState.detail, systemImage: "antenna.radiowaves.left.and.right")
            StatusPill(title: "看门狗", detail: model.watchdogState, systemImage: "eye")
            StatusPill(title: "隧道", detail: model.easyTierState, systemImage: "point.3.connected.trianglepath.dotted")
        }
        .padding(.horizontal, 26)
        .padding(.vertical, 18)
    }
}

private struct StatusPill: View {
    let title: String
    let detail: String
    let systemImage: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.title3)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Text(detail)
                    .lineLimit(1)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct DashboardView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                SectionBox("快速操作") {
                    HStack(spacing: 12) {
                        Button {
                            model.login()
                        } label: {
                            Label("登录", systemImage: "bolt.horizontal.circle.fill")
                        }
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(.borderedProminent)

                        Button {
                            model.logout()
                        } label: {
                            Label("注销", systemImage: "power")
                        }
                        .buttonStyle(.bordered)

                        Button {
                            model.detectCampusParameters()
                        } label: {
                            Label("自动获取认证参数", systemImage: "wand.and.stars")
                        }
                    }
                }

                SectionBox("访问目标检测") {
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(model.settings.probeURLs.indices, id: \.self) { index in
                            HStack {
                                TextField("检测目标 URL", text: $model.settings.probeURLs[index])
                                if index > 0 {
                                    Button(role: .destructive) {
                                        model.settings.probeURLs.remove(at: index)
                                    } label: {
                                        Image(systemName: "minus.circle")
                                    }
                                    .buttonStyle(.borderless)
                                }
                            }
                        }

                        HStack {
                            Button {
                                model.settings.probeURLs.append("https://")
                            } label: {
                                Label("添加目标", systemImage: "plus")
                            }
                            Button {
                                model.checkConnectivity()
                            } label: {
                                Label("立即检测", systemImage: "play.circle")
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(model.isProbing)
                        }

                        if !model.probeResults.isEmpty {
                            ProbeResultsView(results: model.probeResults)
                        }
                    }
                }

                SectionBox("当前配置") {
                    Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 10) {
                        GridRow {
                            FieldSummary("账号", value: model.settings.username)
                            FieldSummary("网关", value: model.settings.esurfingURL)
                        }
                        GridRow {
                            FieldSummary("本机 IP", value: model.settings.wlanUserIP)
                            FieldSummary("AC IP", value: model.settings.wlanACIP)
                        }
                        GridRow {
                            FieldSummary("登录模式", value: model.settings.loginMode.rawValue)
                            FieldSummary("WebUI", value: model.webUIState)
                        }
                    }
                }

            }
            .padding(26)
        }
    }
}

private struct AccountView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section("主账号") {
                RequiredTextField(
                    "学号 / 工号",
                    text: $model.settings.username,
                    isMissing: model.missingFields.contains(.username)
                )
                    .onSubmit { model.reloadPassword() }
                RequiredSecureField(
                    "密码",
                    text: $model.password,
                    isMissing: model.missingFields.contains(.password)
                )
                Picker("登录模式", selection: $model.settings.loginMode) {
                    ForEach(LoginMode.allCases) { mode in
                        Text(mode.rawValue).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
            }

            Section {
                HStack {
                    Button("登录") { model.login() }
                        .buttonStyle(.borderedProminent)
                    Button("注销") { model.logout() }
                }
            }
        }
        .formStyle(.grouped)
        .padding(18)
    }
}

private struct SettingsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section("启动") {
                Toggle("开机自动启动", isOn: $model.settings.launchAtLogin)
                Toggle("启动后自动登录", isOn: $model.settings.autoConnect)
                    .onChange(of: model.settings.autoConnect) { enabled in
                        if enabled {
                            model.settings.savePassword = true
                        }
                    }
                Toggle("记住密码到 macOS Keychain", isOn: $model.settings.savePassword)
                Text("启动后自动登录需要保存密码。开启自动登录时会同时开启 Keychain 保存。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("后台运行") {
                Toggle("登录后开启看门狗", isOn: $model.settings.enableWatchdog)
                HStack {
                    Text("看门狗间隔")
                        .frame(width: 110, alignment: .leading)
                    TextField("秒", value: $model.settings.watchdogTimeout, format: .number)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 90)
                    Text("秒")
                        .foregroundStyle(.secondary)
                }
                Toggle("自动更新本机 IP", isOn: $model.settings.autoUpdateUserIP)
            }

            Section("网络共享") {
                Toggle("启动后自动开启共享", isOn: $model.settings.autoShare)
                Toggle("非本机访问 WebUI 时提供下载页", isOn: $model.settings.easyTier.enableWebDownload)
            }
        }
        .formStyle(.grouped)
        .padding(18)
        .onAppear {
            model.syncLaunchAtLoginStatus()
        }
    }
}

private struct NetworkSettingsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section("ESurfing 参数") {
                RequiredTextField(
                    "认证网关，例如 enet.10000.gd.cn:10001",
                    label: "认证网关",
                    text: $model.settings.esurfingURL,
                    isMissing: model.missingFields.contains(.esurfingURL)
                )
                RequiredTextField(
                    "WLAN AC IP",
                    label: "WLAN AC IP",
                    text: $model.settings.wlanACIP,
                    isMissing: model.missingFields.contains(.wlanACIP)
                )
                HStack {
                    RequiredTextField(
                        "本机登录 IP",
                        label: "本机登录 IP",
                        text: $model.settings.wlanUserIP,
                        isMissing: model.missingFields.contains(.wlanUserIP)
                    )
                }
                Button {
                    model.detectCampusParameters()
                } label: {
                    Label("从广东天翼重定向自动获取", systemImage: "wand.and.stars")
                }
                Button {
                    model.showManualParseSheet = true
                } label: {
                    Label("手动解析", systemImage: "link.badge.plus")
                }
            }

            Section("登录密钥") {
                Text("这是广东天翼登录接口使用的 RSA 公钥，已按 InterKnot 仓库默认值内置，通常不用修改。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button {
                    model.restoreDefaultRSAPublicKey()
                } label: {
                    Label("恢复默认公钥", systemImage: "arrow.counterclockwise")
                }
                DisclosureGroup("高级：查看或替换 RSA 公钥") {
                    TextEditor(text: $model.settings.rsaPublicKey)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 120)
                }
            }

        }
        .formStyle(.grouped)
        .padding(18)
    }
}

private struct MultiLoginView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Button {
                    model.settings.multiAccounts.append(MultiLoginAccount())
                } label: {
                    Label("添加账号", systemImage: "plus")
                }
                Button {
                    model.runMultiLogin()
                } label: {
                    Label("开始多拨", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                Spacer()
            }

            Table($model.settings.multiAccounts) {
                TableColumn("启用") { $account in
                    Toggle("", isOn: $account.enabled)
                        .labelsHidden()
                }
                .width(44)
                TableColumn("名称") { $account in
                    TextField("线路", text: $account.label)
                }
                TableColumn("账号") { $account in
                    TextField("账号", text: $account.username)
                }
                TableColumn("密码") { $account in
                    SecureField("留空使用主密码", text: $account.password)
                }
                TableColumn("IP") { $account in
                    TextField("指定 IP", text: $account.userIP)
                }
            }

            HStack {
                Button(role: .destructive) {
                    model.settings.multiAccounts.removeAll { !$0.enabled && $0.username.isEmpty }
                } label: {
                    Text("清理空行")
                }
                Spacer()
            }
        }
        .padding(26)
    }
}

private struct TunnelView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            Section("EasyTier") {
                TextField("easytier-core 路径", text: $model.settings.easyTier.binaryPath)
                SecureField("网络密钥", text: $model.settings.easyTier.secretKey)
                TextField("对端地址", text: $model.settings.easyTier.peerAddress)
                TextField("虚拟 IP", text: $model.settings.easyTier.virtualIP)
                Toggle("启用 IPv6", isOn: $model.settings.easyTier.enableIPv6)
                Toggle("非本机访问 WebUI 时提供下载页", isOn: $model.settings.easyTier.enableWebDownload)
            }

            Section("操作") {
                HStack {
                    Button {
                        model.startEasyTierServer()
                    } label: {
                        Label("启用共享", systemImage: "arrow.up.arrow.down.circle")
                    }
                    .buttonStyle(.borderedProminent)

                    Button {
                        model.startEasyTierClient()
                    } label: {
                        Label("连接隧道", systemImage: "point.3.connected.trianglepath.dotted")
                    }

                    Button(role: .destructive) {
                        model.stopEasyTier()
                    } label: {
                        Label("停止", systemImage: "stop.circle")
                    }
                }
                Text("macOS 端需要放置可执行的 EasyTier mac 二进制文件；涉及路由或 TUN 权限时，系统可能要求额外授权。")
                    .foregroundStyle(.secondary)
                    .font(.caption)
            }

        }
        .formStyle(.grouped)
        .padding(18)
    }
}

private struct GlobalLogConsole: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Label("运行日志", systemImage: "terminal")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Button {
                    model.logs.removeAll()
                    Logger.clear()
                } label: {
                    Label("清空", systemImage: "trash")
                }
                Button {
                    model.showLogConsole = false
                } label: {
                    Label("收起", systemImage: "chevron.down")
                }
            }
            LogTextView(entries: model.logs)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
    }
}

private struct SectionBox<Content: View>: View {
    let title: String
    let content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.headline)
            content
        }
        .padding(16)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct FieldSummary: View {
    let title: String
    let value: String

    init(_ title: String, value: String) {
        self.title = title
        self.value = value.isEmpty ? "未设置" : value
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.body.monospacedDigit())
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct RequiredTextField: View {
    let placeholder: String
    let label: String?
    @Binding var text: String
    let isMissing: Bool

    init(_ placeholder: String, label: String? = nil, text: Binding<String>, isMissing: Bool) {
        self.placeholder = placeholder
        self.label = label
        self._text = text
        self.isMissing = isMissing
    }

    var body: some View {
        HStack(spacing: 4) {
            if let label {
                Text(label)
                    .frame(width: 110, alignment: .leading)
            }
            RequiredMark(isVisible: isMissing)
            TextField(placeholder, text: $text)
                .textFieldStyle(.roundedBorder)
        }
    }
}

private struct RequiredSecureField: View {
    let placeholder: String
    @Binding var text: String
    let isMissing: Bool

    init(_ placeholder: String, text: Binding<String>, isMissing: Bool) {
        self.placeholder = placeholder
        self._text = text
        self.isMissing = isMissing
    }

    var body: some View {
        HStack(spacing: 4) {
            RequiredMark(isVisible: isMissing)
            SecureField(placeholder, text: $text)
                .textFieldStyle(.roundedBorder)
        }
    }
}

private struct RequiredMark: View {
    let isVisible: Bool

    var body: some View {
        Text("*")
            .font(.headline.weight(.bold))
            .foregroundStyle(isVisible ? .red : .clear)
            .frame(width: 10)
            .accessibilityHidden(!isVisible)
    }
}

private struct ProbeResultsView: View {
    let results: [ProbeResult]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(results) { result in
                HStack(spacing: 10) {
                    Image(systemName: result.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(result.success ? .green : .red)
                    Text(result.target)
                        .lineLimit(1)
                    Spacer()
                    if let latency = result.latencyMS {
                        Text("\(latency) ms")
                            .font(.callout.monospacedDigit())
                    }
                    if let statusCode = result.statusCode {
                        Text("HTTP \(statusCode)")
                            .foregroundStyle(.secondary)
                    } else {
                        Text(result.message)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                .font(.callout)
                .padding(.vertical, 2)
            }
        }
    }
}

private struct LogRows: View {
    let entries: [LogEntry]

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(entries) { entry in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Text(entry.date, style: .time)
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                                .frame(width: 72, alignment: .leading)
                            Text(entry.level)
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(entry.level == "ERROR" ? .red : .secondary)
                                .frame(width: 52, alignment: .leading)
                            Text(entry.message)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .font(.system(.callout, design: .monospaced))
                        .id(entry.id)
                    }
                }
                .padding(12)
            }
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .onChange(of: entries.count) { _ in
                if let last = entries.last {
                    proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
        }
    }
}

private struct LogTextView: View {
    let entries: [LogEntry]

    var body: some View {
        SelectableLogTextView(text: renderedLog)
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private var renderedLog: String {
        entries.map { entry in
            let time = Self.formatter.string(from: entry.date)
            return "\(time)  \(entry.level.padding(toLength: 5, withPad: " ", startingAt: 0))  \(entry.message)"
        }
        .joined(separator: "\n")
    }

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()
}

private struct SelectableLogTextView: NSViewRepresentable {
    let text: String

    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.autohidesScrollers = false
        scrollView.borderType = .noBorder

        let textView = NSTextView()
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        textView.textColor = .labelColor
        textView.backgroundColor = .textBackgroundColor
        textView.textContainerInset = NSSize(width: 8, height: 8)
        textView.textContainer?.widthTracksTextView = true
        textView.textContainer?.containerSize = NSSize(width: scrollView.contentSize.width, height: CGFloat.greatestFiniteMagnitude)
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.isHorizontallyResizable = false
        textView.isVerticallyResizable = true
        textView.autoresizingMask = [.width]
        scrollView.documentView = textView
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        guard let textView = scrollView.documentView as? NSTextView else { return }
        let shouldScroll = isNearBottom(scrollView)
        if textView.string != text {
            textView.string = text
            if shouldScroll || context.coordinator.lastTextCount == 0 {
                textView.scrollToEndOfDocument(nil)
            }
            context.coordinator.lastTextCount = text.count
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    final class Coordinator {
        var lastTextCount = 0
    }

    private func isNearBottom(_ scrollView: NSScrollView) -> Bool {
        guard let documentView = scrollView.documentView else { return true }
        let visible = scrollView.contentView.bounds
        let maxY = documentView.bounds.height
        return maxY - visible.maxY < 40
    }
}

private struct ManualParseSheet: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("手动解析")
                .font(.title3.weight(.semibold))
            Text("浏览器访问 2.2.2.2，复制跳转后的完整地址，粘贴到下方。")
                .foregroundStyle(.secondary)
            TextEditor(text: $model.redirectURLInput)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 120)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
                )

            HStack {
                Spacer()
                Button("取消") {
                    model.showManualParseSheet = false
                }
                Button("解析") {
                    model.parseRedirectURLInput()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 560)
    }
}

private struct CaptchaSheet: View {
    @EnvironmentObject private var model: AppModel
    let challenge: CaptchaChallenge

    var body: some View {
        VStack(spacing: 16) {
            Text(model.captchaTitle)
                .font(.title3.weight(.semibold))
            if let image = NSImage(data: challenge.imageData) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 220, height: 90)
                    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
            }
            TextField("验证码", text: $model.captchaInput)
                .textFieldStyle(.roundedBorder)
                .frame(width: 220)
                .onSubmit { model.submitCaptcha() }

            HStack {
                Button("取消", role: .cancel) { model.cancelCaptcha() }
                Button(model.captchaSubmitTitle) { model.submitCaptcha() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
        .frame(width: 320)
    }
}
