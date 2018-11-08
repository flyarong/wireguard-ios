// SPDX-License-Identifier: MIT
// Copyright © 2018 WireGuard LLC. All Rights Reserved.

import NetworkExtension
import os.log

/// A packet tunnel provider object.
class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: Properties

    private var wgHandle: Int32?
    private var lastError: PacketTunnelProviderError = .noError

    // MARK: NEPacketTunnelProvider

    /// Begin the process of establishing the tunnel.
    override func startTunnel(options: [String: NSObject]?,
                              completionHandler startTunnelCompletionHandler: @escaping (Error?) -> Void) {
        os_log("Starting tunnel", log: OSLog.default, type: .info)

        guard let tunnelProviderProtocol = self.protocolConfiguration as? NETunnelProviderProtocol,
            let tunnelConfiguration = tunnelProviderProtocol.tunnelConfiguration() else {
                let error = PacketTunnelProviderError.savedProtocolConfigurationIsInvalid
                lastError = error
                startTunnelCompletionHandler(error)
                return
        }

        // Resolve endpoint domains

        let endpoints = tunnelConfiguration.peers.map { $0.endpoint }
        var resolvedEndpoints: [Endpoint?] = []
        do {
            resolvedEndpoints = try DNSResolver.resolveSync(endpoints: endpoints)
        } catch DNSResolverError.dnsResolutionFailed(let hostnames) {
            os_log("Starting tunnel failed: DNS resolution failure for %{public}d hostnames (%{public}s)", log: OSLog.default,
                   type: .error, hostnames.count, hostnames.joined(separator: ", "))
            let error = PacketTunnelProviderError.dnsResolutionFailure(hostnames: hostnames)
            lastError = error
            startTunnelCompletionHandler(error)
            return
        } catch {
            // There can be no other errors from DNSResolver.resolveSync()
            fatalError()
        }
        assert(endpoints.count == resolvedEndpoints.count)

        // Setup packetTunnelSettingsGenerator

        let packetTunnelSettingsGenerator = PacketTunnelSettingsGenerator(tunnelConfiguration: tunnelConfiguration,
                                                                          resolvedEndpoints: resolvedEndpoints)

        // Bring up wireguard-go backend

        configureLogger()

        let fd = packetFlow.value(forKeyPath: "socket.fileDescriptor") as! Int32
        if fd < 0 {
            os_log("Starting tunnel failed: Could not determine file descriptor", log: OSLog.default, type: .error)
            let error = PacketTunnelProviderError.couldNotStartWireGuard
            lastError = error
            startTunnelCompletionHandler(error)
            return
        }

        let wireguardSettings = packetTunnelSettingsGenerator.generateWireGuardSettings()
        let handle = connect(interfaceName: tunnelConfiguration.interface.name, settings: wireguardSettings, fd: fd)

        if handle < 0 {
            os_log("Starting tunnel failed: Could not start WireGuard", log: OSLog.default, type: .error)
            startTunnelCompletionHandler(PacketTunnelProviderError.couldNotStartWireGuard)
            let error = PacketTunnelProviderError.couldNotStartWireGuard
            lastError = error
            startTunnelCompletionHandler(error)

            return
        }

        wgHandle = handle

        // Apply network settings

        let networkSettings: NEPacketTunnelNetworkSettings = packetTunnelSettingsGenerator.generateNetworkSettings()
        setTunnelNetworkSettings(networkSettings) { [weak self] (error) in
            if let error = error {
                os_log("Starting tunnel failed: Error setting network settings: %s", log: OSLog.default, type: .error, error.localizedDescription)
                let error = PacketTunnelProviderError.couldNotSetNetworkSettings
                self?.lastError = error
                startTunnelCompletionHandler(error)
            } else {
                startTunnelCompletionHandler(nil /* No errors */)
            }
        }
    }

    /// Begin the process of stopping the tunnel.
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping tunnel", log: OSLog.default, type: .info)
        if let handle = wgHandle {
            wgTurnOff(handle)
        }
        completionHandler()
    }

    // Handle messages from the container app
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        os_log("Handling app message", log: OSLog.default, type: .info)
        guard let requestMessage = PacketTunnelProviderMessage.Request(fromEncodedData: messageData) else {
            completionHandler?(nil)
            return
        }
        switch (requestMessage) {
        case .retrieveLastError:
            let response: PacketTunnelProviderMessage.Response = .lastError(lastError)
            completionHandler?(response.encodeToData())
            return
        }
    }

    private func configureLogger() {
        wgSetLogger { (level, msgCStr) in
            let logType: OSLogType
            switch level {
            case 0:
                logType = .debug
            case 1:
                logType = .info
            case 2:
                logType = .error
            default:
                logType = .default
            }
            let msg = (msgCStr != nil) ? String(cString: msgCStr!) : ""
            os_log("%{public}s", log: OSLog.default, type: logType, msg)
        }
    }

    private func connect(interfaceName: String, settings: String, fd: Int32) -> Int32 { // swiftlint:disable:this cyclomatic_complexity
        return withStringsAsGoStrings(interfaceName, settings) { (nameGoStr, settingsGoStr) -> Int32 in
            return wgTurnOn(nameGoStr, settingsGoStr, fd)
        }
    }
}

private func withStringsAsGoStrings<R>(_ str1: String, _ str2: String, closure: (gostring_t, gostring_t) -> R) -> R {
    return str1.withCString { (s1cStr) -> R in
        let gstr1 = gostring_t(p: s1cStr, n: str1.utf8.count)
        return str2.withCString { (s2cStr) -> R in
            let gstr2 = gostring_t(p: s2cStr, n: str2.utf8.count)
            return closure(gstr1, gstr2)
        }
    }
}
