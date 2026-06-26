import AppKit
import SwiftUI

@main
struct InterKnotAuthApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        WindowGroup("绳网认证", id: "main") {
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
