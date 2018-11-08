// SPDX-License-Identifier: MIT
// Copyright © 2018 WireGuard LLC. All Rights Reserved.

import Foundation

class PacketTunnelProviderMessage {

    enum Request {
        case retrieveLastError
    }

    enum Response {
        case lastError(PacketTunnelProviderError)
    }
}

extension PacketTunnelProviderMessage.Request: Codable {
    // Coding keys
    enum CodingKeys: CodingKey {
        case retrieveLastError
    }

    // Decoding error
    enum DecodingError: Error {
        case invalidInput
    }

    // Encoding
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .retrieveLastError:
            try container.encode(true, forKey: CodingKeys.retrieveLastError)
        }
    }

    // Decoding
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        if let isValid = try? container.decode(Bool.self, forKey: CodingKeys.retrieveLastError), isValid {
            self = .retrieveLastError
            return
        }

        throw DecodingError.invalidInput
    }
}

extension PacketTunnelProviderMessage.Response: Codable {
    // Coding keys
    enum CodingKeys: CodingKey {
        case lastError
    }

    // Decoding error
    enum DecodingError: Error {
        case invalidInput
    }

    // Encoding
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .lastError(let packetTunnelProviderError):
            try container.encode(packetTunnelProviderError, forKey: CodingKeys.lastError)
        }
    }

    // Decoding
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        if let packetTunnelProviderError = try? container.decode(PacketTunnelProviderError.self, forKey: CodingKeys.lastError) {
            self = .lastError(packetTunnelProviderError)
            return
        }

        throw DecodingError.invalidInput
    }
}

extension PacketTunnelProviderMessage.Request {
    func encodeToData() -> Data {
        return try! JSONEncoder().encode(self)
    }
    init?(fromEncodedData encodedData: Data) {
        if let providerError = try? JSONDecoder().decode(PacketTunnelProviderMessage.Request.self, from: encodedData) {
            self = providerError
        }
        return nil
    }
}

extension PacketTunnelProviderMessage.Response {
    func encodeToData() -> Data {
        return try! JSONEncoder().encode(self)
    }
    init?(fromEncodedData encodedData: Data) {
        if let providerError = try? JSONDecoder().decode(PacketTunnelProviderMessage.Response.self, from: encodedData) {
            self = providerError
        }
        return nil
    }
}
