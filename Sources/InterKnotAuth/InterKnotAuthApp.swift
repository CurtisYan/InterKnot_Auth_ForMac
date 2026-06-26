import SwiftUI

@main
struct InterKnotAuthApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
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
    }
}
