import AppKit
import MacAppKit

/// One-shot: unlock, pick an OTP, type it into the previous app, quit.
/// Quitting keeps secrets out of memory, and each launch reopens the picker.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var picker: PickerPanel<Entry>?
    /// Owner of the topmost normal window that isn't ours: the app to type into.
    /// Read before our own prompts steal focus; `frontmostApplication` is stale at launch.
    private let target = (CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]])?
        .first { $0[kCGWindowLayer as String] as? Int == 0 && $0[kCGWindowOwnerPID as String] as? pid_t != getpid() }
        .flatMap { ($0[kCGWindowOwnerPID as String] as? pid_t).flatMap(NSRunningApplication.init) }

    func applicationDidFinishLaunching(_ n: Notification) {
        guard Permissions.isGranted(.accessibility) else {
            Permissions.request(.accessibility)
            return NSApp.terminate(nil)
        }
        do {
            guard let entries = try unlock() else { return NSApp.terminate(nil) }
            show(entries)
        } catch {
            NSApp.activate(ignoringOtherApps: true)
            NSAlert(error: error).runModal()
            NSApp.terminate(nil)
        }
    }

    private func unlock() throws -> [Entry]? {
        let vault = try Vault.load()
        if let key = Keychain.load(), let entries = try? vault.entries(masterKey: key) { return entries }
        var message = "Enter the password for \(Vault.url.path)"
        while let password = askPassword(message) {
            if let key = vault.masterKey(password: password) {
                Keychain.save(key)
                return try vault.entries(masterKey: key)
            }
            message = "Wrong password. Try again."
        }
        return nil
    }

    private func askPassword(_ message: String) -> String? {
        let alert = NSAlert()
        alert.messageText = "Unlock Aegis"
        alert.informativeText = message
        alert.addButton(withTitle: "Unlock")
        alert.addButton(withTitle: "Quit")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        alert.accessoryView = field
        alert.window.initialFirstResponder = field
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn ? field.stringValue : nil
    }

    private func show(_ entries: [Entry]) {
        let picker = PickerPanel<Entry>(title: "Aegis", placeholder: "Search OTPs…",
                                        searchKey: "Picker.lastSearch",
                                        appearance: NSAppearance(named: .darkAqua))
        picker.setFilter { query, entries in
            let q = query.lowercased()
            return entries.compactMap { e -> (Entry, Int)? in
                Fuzzy.score(query: q, target: e.displayText.lowercased()).map { (e, $0) }
            }
            .sorted { $0.1 > $1.1 }.map { $0.0 }
        }
        picker.onPick { _, entry in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { TextInjector.inject(entry.code) }
        }
        // Esc, a pick, or clicking away all take focus from the panel: our cue to quit,
        // once the injected keystrokes are out.
        NotificationCenter.default.addObserver(forName: NSWindow.didResignKeyNotification, object: picker, queue: .main) { _ in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { NSApp.terminate(nil) }
        }
        self.picker = picker
        picker.show(items: entries, returnTo: target)
    }
}

let delegate = AppDelegate()
let app = NSApplication.shared
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
