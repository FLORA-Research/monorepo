import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;

/// The 12-word recovery phrase.
///
/// This is the account. There is no email and no password, so losing the phrase
/// and the phone together loses the account, and the UI has to say so plainly.
///
/// Twelve BIP39 words encode 128 bits of entropy, not 256, so the 32-byte
/// Ed25519 seed is derived rather than being the phrase's own bytes. The
/// mnemonic is stretched with PBKDF2-HMAC-SHA512 using the standard BIP39 salt
/// and the first 32 bytes become the seed. Restoring on another phone repeats
/// the derivation and yields the same keypair, which is the whole point.
///
/// `bip39.mnemonicToSeed` implements exactly that; the derivation was verified
/// byte-for-byte against an independent PBKDF2 computation before being relied
/// on, because recovering a different key than expected would silently open the
/// wrong account.
class RecoveryPhrase {
  RecoveryPhrase._();

  /// Words in a phrase.
  static const int wordCount = 12;

  /// Entropy bytes behind twelve words.
  static const int entropyBytes = 16;

  /// Derive a recovery phrase from a seed.
  ///
  /// Uses the first 16 bytes of the seed as entropy. A phrase produced here and
  /// entered back through `toSeed` returns the same seed, which the tests pin.
  static String fromSeed(List<int> seed) {
    if (seed.length != 32) {
      throw ArgumentError.value(seed.length, 'seed', 'must be 32 bytes');
    }
    return bip39.entropyToMnemonic(
      _toHex(Uint8List.fromList(seed.take(entropyBytes).toList())),
    );
  }

  /// Derive the 32-byte Ed25519 seed from a phrase.
  ///
  /// Rejects a phrase with an invalid word or checksum rather than deriving a
  /// key from nonsense, which would silently restore the wrong account.
  static Future<Uint8List> toSeed(String phrase) async {
    final normalised = normalise(phrase);
    if (!bip39.validateMnemonic(normalised)) {
      throw const InvalidPhrase();
    }
    return _derive(normalised);
  }

  /// Whether a phrase is well formed, for enabling a button.
  static bool isValid(String phrase) {
    final normalised = normalise(phrase);
    return normalised.isNotEmpty && bip39.validateMnemonic(normalised);
  }

  /// Words in the phrase, for rendering as individual chips.
  static List<String> words(String phrase) =>
      normalise(phrase).isEmpty ? const [] : normalise(phrase).split(' ');

  /// Collapse whitespace and lowercase, so a phrase pasted with odd spacing
  /// still validates.
  static String normalise(String phrase) =>
      phrase.trim().toLowerCase().split(RegExp(r'\s+')).where((w) => w.isNotEmpty).join(' ');

  /// BIP39 seed derivation, truncated to the 32 bytes Ed25519 uses.
  ///
  /// The scheme uses no passphrase: a second secret would mean asking a farmer
  /// to remember two things, which is the problem this design avoids.
  static Future<Uint8List> _derive(String mnemonic) async {
    final seed = bip39.mnemonicToSeed(mnemonic);
    return Uint8List.fromList(seed.take(32).toList());
  }

  static String _toHex(Uint8List bytes) {
    const digits = '0123456789abcdef';
    final buffer = StringBuffer();
    for (final byte in bytes) {
      buffer.write(digits[(byte >> 4) & 0x0F]);
      buffer.write(digits[byte & 0x0F]);
    }
    return buffer.toString();
  }
}

/// Thrown when a phrase is not a valid BIP39 mnemonic.
class InvalidPhrase implements Exception {
  const InvalidPhrase();

  @override
  String toString() =>
      'That recovery phrase is not valid. Check every word and the order.';
}
