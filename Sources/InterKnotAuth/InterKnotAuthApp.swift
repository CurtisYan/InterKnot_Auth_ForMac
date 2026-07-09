import AppKit
import Darwin
import SwiftUI

@main
struct InterKnotAuthApp: App {
    @StateObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    init() {
        SingleInstanceGuard.enforce()
        _model = StateObject(wrappedValue: AppModel())
    }

    var body: some Scene {
        Window("绳网认证", id: "main") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 1040, minHeight: 680)
        }
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandMenu("InterKnot") {
                Button("登录") {
                    model.login()
                }
                .keyboardShortcut("l", modifiers: [.command])

                Button("注销") {
                    model.logout()
                }
                .keyboardShortcut("l", modifiers: [.command, .shift])
            }
        }

        MenuBarExtra("绳网认证", systemImage: "link.circle") {
            Button("显示主窗口") {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }

            Divider()

            Button("登录") {
                model.login()
            }

            Button("注销") {
                model.logout()
            }

            Divider()

            Button(model.showLogConsole ? "收起日志" : "显示日志") {
                model.showLogConsole.toggle()
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }

            Divider()

            Button("退出") {
                NSApp.terminate(nil)
            }
        }
    }
}

private enum SingleInstanceGuard {
    static func enforce() {
        let bundleIdentifier = Bundle.main.bundleIdentifier ?? "com.interknot.auth"
        let currentPID = NSRunningApplication.current.processIdentifier
        let existing = NSRunningApplication
            .runningApplications(withBundleIdentifier: bundleIdentifier)
            .first { $0.processIdentifier != currentPID }

        guard let existing else { return }
        existing.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])
        exit(0)
    }
}
