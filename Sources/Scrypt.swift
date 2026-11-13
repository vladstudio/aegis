// scrypt (RFC 7914) — Aegis derives its password key with it; Apple ships no implementation.
import CommonCrypto

enum Scrypt {
    static func derive(_ password: [UInt8], salt: [UInt8], n: Int, r: Int, p: Int, length: Int) -> [UInt8] {
        let words = 32 * r
        var b = pbkdf2(password, salt: salt, length: p * words * 4).withUnsafeBytes { Array($0.bindMemory(to: UInt32.self)) }
        var v = [UInt32](repeating: 0, count: n * words), y = [UInt32](repeating: 0, count: words)
        for i in 0..<p {
            var x = Array(b[i * words..<(i + 1) * words])
            for j in 0..<n {
                v.replaceSubrange(j * words..<(j + 1) * words, with: x)
                blockMix(&x, &y, r)
            }
            for _ in 0..<n {
                let j = Int(x[words - 16]) & (n - 1)
                for k in 0..<words { x[k] ^= v[j * words + k] }
                blockMix(&x, &y, r)
            }
            b.replaceSubrange(i * words..<(i + 1) * words, with: x)
        }
        return pbkdf2(password, salt: b.withUnsafeBytes { Array($0) }, length: length)
    }

    private static func pbkdf2(_ password: [UInt8], salt: [UInt8], length: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: length)
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password.map { CChar(bitPattern: $0) }, password.count,
                             salt, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 1, &out, length)
        return out
    }

    private static func blockMix(_ b: inout [UInt32], _ y: inout [UInt32], _ r: Int) {
        var x = Array(b[(2 * r - 1) * 16..<2 * r * 16])
        for i in 0..<2 * r {
            for k in 0..<16 { x[k] ^= b[i * 16 + k] }
            salsa8(&x)
            y.replaceSubrange((i / 2 + i % 2 * r) * 16..<(i / 2 + i % 2 * r + 1) * 16, with: x)
        }
        swap(&b, &y)
    }

    /// Salsa20/8 core as (a, b, c, d) quarter rounds: 4 columns, then 4 rows.
    private static let quarters = [(0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11),
                                   (0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14)]

    private static func salsa8(_ b: inout [UInt32]) {
        func rotl(_ v: UInt32, _ n: UInt32) -> UInt32 { v << n | v >> (32 - n) }
        var x = b
        for _ in 0..<4 {
            for (a, b, c, d) in quarters {
                x[b] ^= rotl(x[a] &+ x[d], 7)
                x[c] ^= rotl(x[b] &+ x[a], 9)
                x[d] ^= rotl(x[c] &+ x[b], 13)
                x[a] ^= rotl(x[d] &+ x[c], 18)
            }
        }
        for i in 0..<16 { b[i] &+= x[i] }
    }
}
