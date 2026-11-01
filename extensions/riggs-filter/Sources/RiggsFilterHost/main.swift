import Foundation
import NetworkExtension
import SystemExtensions

// Host app for the riggs-filter system extension. macOS only activates system
// extensions whose app is in /Applications, so run it from there:
//
//   "/Applications/Riggs Filter.app/Contents/MacOS/riggs-filter" --activate
//
// --activate    install/upgrade the extension, then turn the content filter on
// --deactivate  turn the content filter off, then uninstall the extension
// --status      print the extension's state and the filter configuration

let extensionID = "com.riggs.filter.extension"

func finish(_ error: Error? = nil) -> Never {
    guard let error else { exit(0) }
    FileHandle.standardError.write(Data("riggs-filter: \(error.localizedDescription)\n".utf8))
    exit(1)
}

func setFilter(enabled: Bool, then next: @escaping () -> Void) {
    let manager = NEFilterManager.shared()
    manager.loadFromPreferences { error in
        if let error { finish(error) }
        guard enabled else {
            guard manager.providerConfiguration != nil else { return next() }
            return manager.removeFromPreferences { error in
                if let error { finish(error) }
                print("content filter removed")
                next()
            }
        }
        let config = NEFilterProviderConfiguration()
        config.filterSockets = true
        config.filterPackets = false
        config.filterDataProviderBundleIdentifier = extensionID
        manager.providerConfiguration = config
        manager.localizedDescription = "Riggs"
        manager.isEnabled = true
        manager.saveToPreferences { error in
            if let error { finish(error) }
            print("content filter enabled")
            next()
        }
    }
}

final class Requests: NSObject, OSSystemExtensionRequestDelegate {
    var onFinish: () -> Void = {}

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        print("replacing extension \(existing.bundleShortVersion) (\(existing.bundleVersion)) with \(ext.bundleShortVersion) (\(ext.bundleVersion))")
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("Approve \"Riggs Filter\" in System Settings > General > Login Items & Extensions > Network Extensions. Waiting...")
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .willCompleteAfterReboot {
            print("the extension change completes after a reboot; rerun this command afterwards")
            finish()
        }
        onFinish()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        finish(error)
    }

    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        if properties.isEmpty { print("extension: not installed") }
        for p in properties {
            print("extension: \(p.bundleIdentifier) \(p.bundleShortVersion) (\(p.bundleVersion)) enabled=\(p.isEnabled) awaitingApproval=\(p.isAwaitingUserApproval) uninstalling=\(p.isUninstalling)")
        }
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            if let error { finish(error) }
            let provider = manager.providerConfiguration?.filterDataProviderBundleIdentifier ?? "none"
            print("content filter: enabled=\(manager.isEnabled) provider=\(provider)")
            finish()
        }
    }
}

let requests = Requests()

func submit(_ request: OSSystemExtensionRequest) {
    request.delegate = requests
    OSSystemExtensionManager.shared.submitRequest(request)
}

switch CommandLine.arguments.dropFirst().first {
case "--activate":
    requests.onFinish = { print("extension active"); setFilter(enabled: true) { finish() } }
    submit(.activationRequest(forExtensionWithIdentifier: extensionID, queue: .main))
case "--deactivate":
    requests.onFinish = { print("extension deactivated"); finish() }
    setFilter(enabled: false) { submit(.deactivationRequest(forExtensionWithIdentifier: extensionID, queue: .main)) }
case "--status":
    submit(.propertiesRequest(forExtensionWithIdentifier: extensionID, queue: .main))
default:
    print("usage: riggs-filter --activate | --deactivate | --status")
    exit(64)
}
dispatchMain()
