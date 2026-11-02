import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../../core/protocol.dart';
import '../protocol/canonical.dart';

/// A parsed `flora://pair?v=1&id=..&ct=..&u=..` QR payload.
class QrPayload {
  const QrPayload({
    required this.deviceId,
    required this.claimToken,
    this.uuid,
  });

  /// The gateway's 32-character hex device id.
  final String deviceId;

  /// 32-byte claim token, hex.
  final String claimToken;

  /// The device's own uuid, printed in the QR but not used by the claim. Kept
  /// so the app can show which hardware it is pairing with.
  final String? uuid;

  /// Decoded claim token bytes, which are what the signature covers.
  Uint8List get claimTokenBytes {
    final bytes = Canonical.hexDecode(claimToken);
    if (bytes == null || bytes.length != Protocol.tokenLength) {
      throw const PairingError('This QR code is damaged. Ask for a new one.');
    }
    return bytes;
  }

  /// Parse a scanned string.
  ///
  /// Rejects anything that is not a FLORA pairing code, so scanning a random QR
  /// gives a clear message rather than a confusing failure later.
  static QrPayload parse(String raw) {
    final trimmed = raw.trim();
    if (trimmed.isEmpty) {
      throw const PairingError('Nothing was read from the code.');
    }

    final uri = Uri.tryParse(trimmed);
    if (uri == null || uri.scheme != Protocol.pairScheme || uri.host != Protocol.pairHost) {
      throw const PairingError(
        'That is not a FLORA pairing code. Look for the code that came with the device.',
      );
    }

    final version = uri.queryParameters['v'];
    if (version == null || int.tryParse(version) != Protocol.pairVersion) {
      throw PairingError(
        'This pairing code is version ${version ?? "unknown"}, which this app does not understand. Update the app.',
      );
    }

    final deviceId = uri.queryParameters['id']?.trim().toLowerCase();
    if (deviceId == null || deviceId.length != Protocol.gatewayIdHexLength) {
      throw const PairingError('The pairing code is missing the device identifier.');
    }
    if (Canonical.hexDecode(deviceId) == null) {
      throw const PairingError('The device identifier in this code is not valid.');
    }

    final claimToken = uri.queryParameters['ct']?.trim().toLowerCase();
    if (claimToken == null ||
        claimToken.length != Protocol.tokenLength * 2 ||
        Canonical.hexDecode(claimToken) == null) {
      throw const PairingError('The pairing code is missing a valid claim token.');
    }

    final uuid = uri.queryParameters['u']?.trim().toLowerCase();
    return QrPayload(
      deviceId: deviceId,
      claimToken: claimToken,
      uuid: (uuid != null && uuid.length == Protocol.nodeUuidLength * 2) ? uuid : null,
    );
  }
}

/// A 16-byte single-use nonce.
///
/// Random per attempt, because the server rejects a repeated nonce. Taken from
/// `Random.secure`, since a predictable nonce would let an attacker precompute
/// a claim they cannot otherwise forge.
Uint8List freshNonce() {
  final random = Random.secure();
  final nonce = Uint8List(Protocol.nonceLength);
  for (var index = 0; index < nonce.length; index++) {
    nonce[index] = random.nextInt(256);
  }
  return nonce;
}

/// Whether the platform keystore is usable.
///
/// `flutter_secure_storage` throws on a platform without a keystore, and the
/// old app surfaced that as an error screen during ordinary actions. Checking
/// once at start lets the UI explain the problem instead.
class SecureStorageProbe {
  SecureStorageProbe({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  /// Write and read a probe value. Returns the failure message, or null when
  /// storage works.
  Future<String?> probe() async {
    const key = 'flora.probe';
    try {
      await _storage.write(key: key, value: 'ok');
      final value = await _storage.read(key: key);
      await _storage.delete(key: key);
      if (value != 'ok') {
        return 'Secure storage did not return what was written.';
      }
      return null;
    } catch (error) {
      return 'This device cannot store keys securely: $error';
    }
  }
}

/// The platform keystore cannot be reached.
///
/// Distinct from "no key stored": the key may exist but be unreadable, and
/// treating that as absent would mint a second identity and strand the first
/// account. Callers must surface this rather than start fresh.
class KeystoreUnavailable implements Exception {
  const KeystoreUnavailable(this.message);

  final String message;

  @override
  String toString() => message;
}

/// A pairing or storage problem a person can act on.
class PairingError implements Exception {
  const PairingError(this.message);

  final String message;

  @override
  String toString() => message;
}
