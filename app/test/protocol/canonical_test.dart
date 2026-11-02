import 'dart:typed_data';

import 'package:flora_app/core/protocol.dart';
import 'package:flora_app/data/protocol/canonical.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('canonical command message', () {
    test('matches the Rust vector byte for byte', () {
      // The same inputs as `flora-protocol`'s own test and the aggregator's
      // parity test. If this drifts, commands stop verifying in the field and
      // the failure appears nowhere near the cause.
      final message = Canonical.command(
        kind: Protocol.kindSetValve,
        gatewayId: _ascii('agg-0001agg-0001'),
        nodeAddr: 4,
        nonce: 7,
        timestamp: 9,
        payload: [1, 0, 30, 0],
      );

      expect(
        Canonical.hex(message),
        '01016167672d303030316167672d3030303104000000070000000901001e00',
      );
      expect(message.length, Protocol.canonicalMessageLength);
      expect(message.length, 31);
    });

    test('lays out every field at the documented offset', () {
      final message = Canonical.command(
        kind: Protocol.kindSetThreshold,
        gatewayId: _ascii('agg-0001agg-0001'),
        nodeAddr: 2,
        nonce: 0x01020304,
        timestamp: 0x05060708,
        payload: [0, 200, 2, 188],
      );

      expect(message[0], 0x01, reason: 'canonical version');
      expect(message[1], Protocol.kindSetThreshold, reason: 'kind');
      expect(message.sublist(2, 18), _ascii('agg-0001agg-0001'),
          reason: 'full 16-byte gateway id');
      expect(message[18], 2, reason: 'node address');
      expect(message.sublist(19, 23), [1, 2, 3, 4], reason: 'nonce, big-endian');
      expect(message.sublist(23, 27), [5, 6, 7, 8], reason: 'timestamp, big-endian');
      expect(message.sublist(27, 31), [0, 200, 2, 188], reason: 'payload');
    });

    test('binds the whole gateway id, not a prefix', () {
      // Two ids sharing their first fifteen bytes must not sign the same bytes,
      // or one aggregator could accept another's command.
      final first = Canonical.command(
        kind: Protocol.kindSetValve,
        gatewayId: _ascii('agg-0001agg-0001'),
        nodeAddr: 4,
        nonce: 1,
        timestamp: 1,
        payload: [1, 0, 0, 0],
      );
      final second = Canonical.command(
        kind: Protocol.kindSetValve,
        gatewayId: _ascii('agg-0001agg-0002'),
        nodeAddr: 4,
        nonce: 1,
        timestamp: 1,
        payload: [1, 0, 0, 0],
      );
      expect(first.sublist(0, 15), second.sublist(0, 15));
      expect(first, isNot(second));
    });

    test('rejects a wrong-size gateway id or payload', () {
      expect(
        () => Canonical.command(
          kind: Protocol.kindSetValve,
          gatewayId: _ascii('agg-0001'),
          nodeAddr: 4,
          nonce: 1,
          timestamp: 1,
          payload: [1, 0, 0, 0],
        ),
        throwsArgumentError,
        reason: 'an 8-byte id is the old width and must not be accepted',
      );
      expect(
        () => Canonical.command(
          kind: Protocol.kindSetValve,
          gatewayId: _ascii('agg-0001agg-0001'),
          nodeAddr: 4,
          nonce: 1,
          timestamp: 1,
          payload: [1, 0],
        ),
        throwsArgumentError,
      );
    });
  });

  group('pairing and auth signing inputs', () {
    test('pairing message has the documented prefix, separator, and order', () {
      final claimToken = Uint8List.fromList(List.filled(32, 0xAB));
      final nonce = Uint8List.fromList(List.filled(16, 0xCD));
      final message = Canonical.pairingClaim(
        deviceId: 'fe812c12f3ab4ce6ac5db69ac352f906',
        claimToken: claimToken,
        nonce: nonce,
      );

      // The prefix is 13 bytes: "flora-pair-v1". Getting this wrong shifts
      // every following field, which is exactly the mistake that makes a
      // signature fail with no useful error.
      expect(message.sublist(0, 13), _ascii('flora-pair-v1'));
      expect(
        message.sublist(13, 13 + 32),
        _ascii('fe812c12f3ab4ce6ac5db69ac352f906'),
        reason: 'the device id as text, not decoded',
      );
      expect(message[45], 0x00, reason: 'the separator at offset 13 + 32');
      expect(message.sublist(46, 78), claimToken);
      expect(message.sublist(78, 94), nonce);
      expect(message.length, 94);
    });

    test('auth message has no separator and uses the raw public key', () {
      final publicKey = Uint8List.fromList(List.filled(32, 0x11));
      final nonce = Uint8List.fromList(List.filled(32, 0x22));
      final message = Canonical.auth(publicKey: publicKey, nonce: nonce);

      expect(message.sublist(0, 13), _ascii('flora-auth-v1'));
      expect(message.sublist(13, 45), publicKey);
      expect(message.sublist(45, 77), nonce);
      expect(message.length, 77);
    });

    test('the two flows are domain separated', () {
      // A signature made for one must not be replayable into the other.
      final pairing = Canonical.pairingClaim(
        deviceId: 'ab',
        claimToken: Uint8List(32),
        nonce: Uint8List(16),
      );
      final auth = Canonical.auth(publicKey: Uint8List(32), nonce: Uint8List(16));
      expect(pairing.sublist(0, 13), isNot(auth.sublist(0, 13)));
    });
  });

  group('device id derivation', () {
    test('matches the provisioner and cloud vector', () async {
      // SHA-256 of bytes 0x00..0x1f, truncated to 16, hex. The same literal is
      // pinned in `flora-protocol` and in the provisioner's tests.
      final publicKey = Uint8List.fromList(List.generate(32, (index) => index));
      expect(await Canonical.deviceId(publicKey), '630dcd2966c4336691125448bbb25b4f');
    });

    test('rejects a wrong-size public key', () async {
      expect(() => Canonical.deviceId(Uint8List(31)), throwsArgumentError);
    });
  });

  group('payload encoders', () {
    test('valve payload is state, duration high, duration low, reserved', () {
      expect(Canonical.valvePayload(open: true, durationSeconds: 300), [1, 0x01, 0x2C, 0]);
      expect(Canonical.valvePayload(open: false, durationSeconds: 0), [0, 0, 0, 0]);
      expect(() => Canonical.valvePayload(open: true, durationSeconds: 70000), throwsArgumentError);
    });

    test('threshold payload is per mille and refuses an inverted band', () {
      expect(Canonical.thresholdPayload(dry: 200, wet: 700), [0, 200, 2, 188]);
      expect(() => Canonical.thresholdPayload(dry: 700, wet: 600), throwsArgumentError);
      expect(() => Canonical.thresholdPayload(dry: 200, wet: 200), throwsArgumentError);
      expect(() => Canonical.thresholdPayload(dry: 0, wet: 1001), throwsArgumentError);
    });

    test('calibrate payload encodes the mode', () {
      expect(Canonical.calibratePayload(dryReference: true), [0, 0, 0, 0]);
      expect(Canonical.calibratePayload(dryReference: false), [1, 0, 0, 0]);
    });
  });

  group('hex', () {
    test('round trips and rejects malformed input', () {
      expect(Canonical.hex([0x00, 0x0F, 0xFF]), '000fff');
      expect(Canonical.hexDecode('000fff'), [0x00, 0x0F, 0xFF]);
      expect(Canonical.hexDecode('000FFF'), [0x00, 0x0F, 0xFF], reason: 'uppercase is accepted');
      expect(Canonical.hexDecode('abc'), isNull, reason: 'odd length');
      expect(Canonical.hexDecode('zz'), isNull);
    });
  });
}

/// ASCII bytes of a literal, for building fixed vectors.
Uint8List _ascii(String value) => Uint8List.fromList(value.codeUnits);
