import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../../core/protocol.dart';
import '../pairing/qr_payload.dart';
import '../protocol/canonical.dart';

/// The app's Ed25519 keypair.
///
/// The private key lives in the platform keystore and never leaves the device.
/// That is the whole reason there is no password: the phone holds a key, and
/// proving possession of it is the credential.
///
/// Nothing here is ever sent to the cloud. In particular the recovery phrase is
/// handled locally, so a server compromise cannot yield the key.
class AppKeypair {
  AppKeypair._({required this.keyPair, required this.publicKey});

  final SimpleKeyPair keyPair;

  /// Raw 32-byte public key, the form every canonical encoding uses.
  final Uint8List publicKey;

  /// Hex public key, the form the API accepts.
  String get publicKeyHex => Canonical.hex(publicKey);

  /// Device id derived from this key: `SHA-256(pubkey)[..16]`.
  ///
  /// Not used for a phone, but useful for a self-test that the derivation
  /// matches the provisioner.
  Future<String> derivedDeviceId() => Canonical.deviceId(publicKey);

  /// Sign canonical bytes, returning the 64-byte signature.
  Future<Uint8List> sign(List<int> message) async {
    final signature = await Ed25519().sign(message, keyPair: keyPair);
    final bytes = Uint8List.fromList(signature.bytes);
    if (bytes.length != Protocol.signatureLength) {
      throw StateError('signature is ${bytes.length} bytes');
    }
    return bytes;
  }
}

/// Loads, creates, and destroys the app keypair.
///
/// The seed is stored rather than the derived keypair so a restore from the
/// recovery phrase reproduces the same identity exactly. Twelve BIP39 words
/// carry 128 bits, so the seed is 16 bytes and is stretched to the 32-byte
/// Ed25519 seed with PBKDF2-HMAC-SHA512, matching the BIP39 specification.
class KeypairStore {
  KeypairStore({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  static const _seedKey = 'flora.keypair.seed';

  final FlutterSecureStorage _storage;

  /// Read the stored keypair, or create one if this is a fresh install.
  Future<AppKeypair> loadOrCreate() async {
    final existing = await _read();
    if (existing != null) return _fromSeed(existing);
    final seed = await _randomSeed();
    await _write(seed);
    return _fromSeed(seed);
  }

  /// The stored keypair, or null when the app has none yet.
  ///
  /// Distinct from `loadOrCreate` so a caller can render the accountless shell
  /// without creating an identity the user never asked for.
  Future<AppKeypair?> load() async {
    final seed = await _read();
    return seed == null ? null : _fromSeed(seed);
  }

  /// Whether a keypair exists, without decoding it.
  Future<bool> exists() async => (await _read()) != null;

  /// Replace the stored keypair, used by recovery from a phrase.
  ///
  /// Overwrites whatever was there: restoring must yield the account that owns
  /// the phrase, not a merge with the previous local identity.
  Future<AppKeypair> replaceWithSeed(List<int> seed) async {
    if (seed.length != 32) {
      throw ArgumentError.value(seed.length, 'seed', 'must be 32 bytes');
    }
    await _write(Uint8List.fromList(seed));
    return _fromSeed(Uint8List.fromList(seed));
  }

  /// Export the seed so a recovery phrase can be shown.
  ///
  /// Callers must treat this as the account itself.
  Future<Uint8List?> exportSeed() => _read();

  /// Forget the identity. Used when the user signs out on this device.
  Future<void> clear() => _delete();

  Future<AppKeypair> _fromSeed(Uint8List seed) async {
    if (seed.length != 32) {
      throw StateError('stored seed is ${seed.length} bytes, expected 32');
    }
    final keyPair = await Ed25519().newKeyPairFromSeed(seed);
    final publicKey = await keyPair.extractPublicKey();
    return AppKeypair._(
      keyPair: keyPair,
      publicKey: Uint8List.fromList(publicKey.bytes),
    );
  }

  Future<Uint8List?> _read() async {
    final String? stored;
    try {
      stored = await _storage.read(key: _seedKey);
    } catch (error) {
      // A keystore that cannot be read is not the same as no keystore: the key
      // may exist and be unreachable. Reporting it as absent would silently
      // create a second identity and strand the first account, so this is an
      // error the user must see.
      throw KeystoreUnavailable(_explain(error));
    }
    if (stored == null || stored.isEmpty) return null;
    final Uint8List seed;
    try {
      seed = Uint8List.fromList(base64Decode(stored));
    } on FormatException {
      // Stored value is not valid base64: treat as absent rather than crashing
      // the app on launch.
      return null;
    }
    // A truncated or foreign value must not be treated as a key.
    if (seed.length != 32) return null;
    return seed;
  }

  Future<void> _write(Uint8List seed) async {
    try {
      await _storage.write(key: _seedKey, value: base64Encode(seed));
    } catch (error) {
      throw KeystoreUnavailable(_explain(error));
    }
  }

  Future<void> _delete() async {
    try {
      await _storage.delete(key: _seedKey);
    } catch (error) {
      throw KeystoreUnavailable(_explain(error));
    }
  }

  /// Turn a platform failure into something a person can act on.
  static String _explain(Object error) {
    final text = error.toString();
    if (text.contains('MissingPluginException')) {
      return 'This build cannot reach the device keystore. Reinstall the app from '
          'the APK, and do not run it as a background service.';
    }
    return 'FLORA could not reach this device its secure storage, so it cannot '
        'protect your account key. Restart the phone and try again.';
  }

  /// A cryptographically random 32-byte seed.
  ///
  /// Taken from the library's generator rather than from `dart:math`, which is
  /// not suitable for key material. The generator seeds from the platform's
  /// secure random source.
  static Future<Uint8List> _randomSeed() async {
    final keyPair = await Ed25519().newKeyPair();
    final seed = await keyPair.extractPrivateKeyBytes();
    if (seed.length != 32) {
      throw StateError('generated seed is ${seed.length} bytes, expected 32');
    }
    return Uint8List.fromList(seed);
  }
}
