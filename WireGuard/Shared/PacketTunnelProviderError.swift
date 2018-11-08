// SPDX-License-Identifier: MIT
// Copyright © 2018 WireGuard LLC. All Rights Reserved.

import Foundation

enum PacketTunnelProviderError: Error {
    case noError
    case savedProtocolConfigurationIsInvalid
    case dnsResolutionFailure(hostnames: [String])
    case couldNotStartWireGuard
    case couldNotSetNetworkSettings
}

extension PacketTunnelProviderError: Codable {
    // Coding keys
    enum CodingKeys: CodingKey {
        case noError
        case savedProtocolConfigurationIsInvalid
        case dnsResolutionFailure
        case couldNotStartWireGuard
        case couldNotSetNetworkSettings
    }

    // Decoding error
    enum DecodingError: Error {
        case invalidInput
    }

    // Encoding
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .noError:
            try container.encode(true, forKey: CodingKeys.noError)
        case .savedProtocolConfigurationIsInvalid:
            try container.encode(true, forKey: CodingKeys.savedProtocolConfigurationIsInvalid)
        case .dnsResolutionFailure(let hostnames):
            try container.encode(hostnames, forKey: CodingKeys.dnsResolutionFailure)
        case .couldNotStartWireGuard:
            try container.encode(true, forKey: CodingKeys.couldNotStartWireGuard)
        case .couldNotSetNetworkSettings:
            try container.encode(true, forKey: CodingKeys.couldNotSetNetworkSettings)
        }
    }

    // Decoding
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        if let isValid = try? container.decode(Bool.self, forKey: CodingKeys.noError), isValid {
            self = .noError
            return
        }

        if let isValid = try? container.decode(Bool.self, forKey: CodingKeys.savedProtocolConfigurationIsInvalid), isValid {
            self = .savedProtocolConfigurationIsInvalid
            return
        }

        if let hostnames = try? container.decode([String].self, forKey: CodingKeys.dnsResolutionFailure) {
            self = .dnsResolutionFailure(hostnames: hostnames)
            return
        }

        if let isValid = try? container.decode(Bool.self, forKey: CodingKeys.couldNotStartWireGuard), isValid {
            self = .couldNotStartWireGuard
            return
        }

        if let isValid = try? container.decode(Bool.self, forKey: CodingKeys.couldNotSetNetworkSettings), isValid {
            self = .couldNotSetNetworkSettings
            return
        }

        throw DecodingError.invalidInput
    }
}

extension PacketTunnelProviderError {
    func encodeToData() -> Data {
        return try! JSONEncoder().encode(self)
    }
    init?(fromEncodedData encodedData: Data) {
        if let providerError = try? JSONDecoder().decode(PacketTunnelProviderError.self, from: encodedData) {
            self = providerError
        }
        return nil
    }
}
