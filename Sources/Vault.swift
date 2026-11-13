// Aegis vault format: password slots wrap the master key, which decrypts the entries.
// https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md
import CryptoKit
import Foundation
import MacAppKit

struct Vault: Decodable {
    struct Params: Decodable { let nonce, tag: String }
    struct Slot: Decodable { let type: Int; let key: String; let keyParams: Params; let n, r, p: Int?; let salt: String? }
    struct Header: Decodable { let slots: [Slot]; let params: Params }
    let header: Header
    let db: String

    static let url = FileManager.default.homeDirectoryForCurrentUser.appending(path: "aegis.json")

    static func load() throws -> Vault {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Vault.self, from: Data(contentsOf: url))
    }

    /// Tries `password` against every password slot (type 1); nil if none opens.
    func masterKey(password: String) -> SymmetricKey? {
        for s in header.slots where s.type == 1 {
            guard let n = s.n, let r = s.r, let p = s.p, let salt = s.salt else { continue }
            let derived = Scrypt.derive(Array(password.utf8), salt: Array(hex(salt)), n: n, r: r, p: p, length: 32)
            if let key = try? open(hex(s.key), s.keyParams, SymmetricKey(data: derived)) { return SymmetricKey(data: key) }
        }
        return nil
    }

    func entries(masterKey: SymmetricKey) throws -> [Entry] {
        struct DB: Decodable { let entries: [Entry] }
        let json = try open(Data(base64Encoded: db) ?? Data(), header.params, masterKey)
        return try JSONDecoder().decode(DB.self, from: json).entries.filter { $0.type == "totp" }
    }

    private func open(_ ciphertext: Data, _ params: Params, _ key: SymmetricKey) throws -> Data {
        let box = try AES.GCM.SealedBox(nonce: .init(data: hex(params.nonce)), ciphertext: ciphertext, tag: hex(params.tag))
        return try AES.GCM.open(box, using: key)
    }

    private func hex(_ s: String) -> Data {
        let c = Array(s.utf8)
        return Data(stride(from: 0, to: c.count - 1, by: 2).compactMap { UInt8(String(decoding: c[$0...$0 + 1], as: UTF8.self), radix: 16) })
    }
}

struct Entry: Decodable, Pickable {
    struct Info: Decodable { let secret, algo: String; let digits: Int; let period: Int? }
    let type, name, issuer: String
    let info: Info

    var displayText: String { [issuer, name].filter { !$0.isEmpty }.joined(separator: " · ") }

    /// RFC 6238 TOTP for the current time.
    var code: String {
        let counter = withUnsafeBytes(of: UInt64(Date().timeIntervalSince1970) / UInt64(info.period ?? 30)) { Data($0.reversed()) }
        let key = SymmetricKey(data: base32(info.secret))
        let mac: [UInt8] = switch info.algo {
        case "SHA256": Array(HMAC<SHA256>.authenticationCode(for: counter, using: key))
        case "SHA512": Array(HMAC<SHA512>.authenticationCode(for: counter, using: key))
        default: Array(HMAC<Insecure.SHA1>.authenticationCode(for: counter, using: key))
        }
        let o = Int(mac[mac.count - 1] & 0xf)
        let bin = mac[o..<o + 4].reduce(0) { $0 << 8 | Int($1) } & 0x7fff_ffff
        return String(format: "%0*d", info.digits, bin % Int(pow(10, Double(info.digits))))
    }

    private func base32(_ s: String) -> Data {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = Data(), acc = 0, bits = 0
        for c in s.uppercased() {
            guard let v = alphabet.firstIndex(of: c) else { continue }
            acc = (acc << 5 | v) & 0xffff
            bits += 5
            if bits >= 8 { bits -= 8; out.append(UInt8(acc >> bits & 0xff)) }
        }
        return out
    }
}

/// The unwrapped master key, so the password (and slow scrypt) is needed only once.
enum Keychain {
    private static var item: [CFString: Any] {
        [kSecClass: kSecClassGenericPassword, kSecAttrService: "studio.vlad.aegis", kSecAttrAccount: "master-key"]
    }

    static func load() -> SymmetricKey? {
        var out: CFTypeRef?
        SecItemCopyMatching(item.merging([kSecReturnData: true]) { $1 } as CFDictionary, &out)
        return (out as? Data).map { SymmetricKey(data: $0) }
    }

    static func save(_ key: SymmetricKey) {
        SecItemDelete(item as CFDictionary)
        SecItemAdd(item.merging([kSecValueData: key.withUnsafeBytes { Data($0) }]) { $1 } as CFDictionary, nil)
    }
}
