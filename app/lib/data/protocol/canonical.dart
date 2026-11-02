import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../../core/protocol.dart';

/// Canonical byte encodings.
///
/// These produce exactly the bytes the Rust crates produce. Both sides sign the
/// same buffer, so a byte out of place means a signature the device rejects,
/// and the failure surfaces far from the cause. The offsets below are therefore
/// duplicated as tests against a literal vector taken from the Rust tests.
class Canonical {
  Canonical._();

  /// The message an app signs to authorise a manual command.
  ///
  /// Layout, all integers big-endian:
  /// `version(1) kind(1) gateway_id(16) node_addr(1) nonce(4) timestamp(4)
  /// payload(4)`.
  ///
  /// The full 16-byte gateway id is covered. Signing only a prefix would let a
  /// command signed for one aggregator verify against another whose id shares
  /// those leading bytes.
  static Uint8List command({
    required int kind,
    required List<int> gatewayId,
    required int nodeAddr,
    required int nonce,
    required int timestamp,
    required List<int> payload,
  }) {
    if (gatewayId.length != Protocol.gatewayIdLength) {
      throw ArgumentError.value(
        gatewayId.length,
        'gatewayId',
        'must be ${Protocol.gatewayIdLength} bytes',
      );
    }
    if (payload.length != Protocol.payloadLength(kind)) {
      throw ArgumentError.value(
        payload.length,
        'payload',
        'must be ${Protocol.payloadLength(kind)} bytes for kind $kind',
      );
    }

    final builder = BytesBuilder(copy: false)
      ..addByte(Protocol.canonicalVersion)
      ..addByte(kind)
      ..add(gatewayId)
      ..addByte(nodeAddr);
    _addUint32(builder, nonce);
    _addUint32(builder, timestamp);
    builder.add(payload);

    final message = builder.takeBytes();
    if (message.length != Protocol.canonicalMessageLength) {
      throw StateError(
        'canonical message is ${message.length} bytes, '
        'expected ${Protocol.canonicalMessageLength}',
      );
    }
    return message;
  }

  /// The message an app signs to claim a gateway.
  ///
  /// `"flora-pair-v1" || device_id || 0x00 || claim_token || nonce`, from
  /// `ClaimSignatureInput::message`. The separator stops an ambiguous
  /// concatenation where two different device-id and token pairs produce the
  /// same bytes.
  static Uint8List pairingClaim({
    required String deviceId,
    required List<int> claimToken,
    required List<int> nonce,
  }) {
    final builder = BytesBuilder(copy: false)
      ..add(_ascii(Protocol.pairingPrefix))
      ..add(_ascii(deviceId))
      ..addByte(0x00)
      ..add(claimToken)
      ..add(nonce);
    return builder.takeBytes();
  }

  /// The message an app signs to authenticate.
  ///
  /// `"flora-auth-v1" || pubkey || nonce`, from `auth_message`. Distinct from
  /// the pairing prefix by construction.
  static Uint8List auth({
    required List<int> publicKey,
    required List<int> nonce,
  }) {
    final builder = BytesBuilder(copy: false)
      ..add(_ascii(Protocol.authPrefix))
      ..add(publicKey)
      ..add(nonce);
    return builder.takeBytes();
  }

  /// Device id from a public key: `SHA-256(pubkey)[..16]`, lowercase hex.
  ///
  /// Matches `flora_protocol::derive_device_id`, so a device flashed by the
  /// provisioner is recognised here. Must be asynchronous because the digest is.
  static Future<String> deviceId(List<int> publicKey) async {
    if (publicKey.length != Protocol.publicKeyLength) {
      throw ArgumentError.value(
        publicKey.length,
        'publicKey',
        'must be ${Protocol.publicKeyLength} bytes',
      );
    }
    final digest = await Sha256().hash(publicKey);
    return _hex(digest.bytes.take(16).toList());
  }

  /// Four-byte payload for `set_valve`: `state, duration_hi, duration_lo, 0`.
  static List<int> valvePayload({required bool open, required int durationSeconds}) {
    if (durationSeconds < 0 || durationSeconds > 0xFFFF) {
      throw ArgumentError.value(durationSeconds, 'durationSeconds', 'must fit in u16');
    }
    return [
      open ? 1 : 0,
      (durationSeconds >> 8) & 0xFF,
      durationSeconds & 0xFF,
      0,
    ];
  }

  /// Four-byte payload for `set_threshold`: `dry_hi, dry_lo, wet_hi, wet_lo`.
  ///
  /// Both are per mille. The cloud and the device both reject an inverted band,
  /// so validating here gives a clear message instead of a 400.
  static List<int> thresholdPayload({required int dry, required int wet}) {
    if (dry < 0 || dry > 1000 || wet < 0 || wet > 1000) {
      throw ArgumentError('thresholds are per mille, so at most 1000');
    }
    if (wet <= dry) {
      throw ArgumentError('the wet threshold must be above the dry threshold');
    }
    return [(dry >> 8) & 0xFF, dry & 0xFF, (wet >> 8) & 0xFF, wet & 0xFF];
  }

  /// Four-byte payload for `calibrate`: `mode, 0, 0, 0`.
  static List<int> calibratePayload({required bool dryReference}) {
    return [dryReference ? 0 : 1, 0, 0, 0];
  }

  static void _addUint32(BytesBuilder builder, int value) {
    if (value < 0 || value > 0xFFFFFFFF) {
      throw ArgumentError.value(value, 'value', 'must fit in u32');
    }
    builder
      ..addByte((value >> 24) & 0xFF)
      ..addByte((value >> 16) & 0xFF)
      ..addByte((value >> 8) & 0xFF)
      ..addByte(value & 0xFF);
  }

  static List<int> _ascii(String value) {
    final bytes = <int>[];
    for (final rune in value.codeUnits) {
      if (rune > 0x7F) {
        throw ArgumentError.value(value, 'value', 'must be ASCII');
      }
      bytes.add(rune);
    }
    return bytes;
  }

  static String _hex(List<int> bytes) {
    const digits = '0123456789abcdef';
    final buffer = StringBuffer();
    for (final byte in bytes) {
      buffer.write(digits[(byte >> 4) & 0x0F]);
      buffer.write(digits[byte & 0x0F]);
    }
    return buffer.toString();
  }

  /// Decode lowercase or uppercase hex, returning null for anything malformed.
  static Uint8List? hexDecode(String value) {
    if (value.length.isOdd) return null;
    final bytes = Uint8List(value.length ~/ 2);
    for (var index = 0; index < bytes.length; index++) {
      final high = _nibble(value.codeUnitAt(index * 2));
      final low = _nibble(value.codeUnitAt(index * 2 + 1));
      if (high < 0 || low < 0) return null;
      bytes[index] = (high << 4) | low;
    }
    return bytes;
  }

  static int _nibble(int codeUnit) {
    if (codeUnit >= 0x30 && codeUnit <= 0x39) return codeUnit - 0x30;
    if (codeUnit >= 0x61 && codeUnit <= 0x66) return codeUnit - 0x61 + 10;
    if (codeUnit >= 0x41 && codeUnit <= 0x46) return codeUnit - 0x41 + 10;
    return -1;
  }

  static String hex(List<int> bytes) => _hex(bytes);
}
