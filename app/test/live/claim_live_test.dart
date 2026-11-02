@Tags(['live'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dio/dio.dart';
import 'package:flora_app/core/protocol.dart';
import 'package:flora_app/data/api/api_client.dart';
import 'package:flora_app/data/api/cloud_repository.dart';
import 'package:flora_app/data/auth/keypair.dart';
import 'package:flora_app/data/auth/session.dart';
import 'package:flora_app/data/pairing/qr_payload.dart';
import 'package:flora_app/data/protocol/canonical.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

/// Runs the app's own client code against a real server.
///
/// The unit tests prove the byte layouts match the documented vectors. This
/// proves the whole path: the app signs, the server verifies with its own Rust
/// implementation, and the resulting session can read the account. That is the
/// check that catches a mismatch no amount of local testing would.
///
/// Skipped unless `FLORA_LIVE_URL` and `FLORA_LIVE_PROVISION_KEY` are set, so
/// the suite still runs on a machine with no server.
void main() {
  final baseUrl = Platform.environment['FLORA_LIVE_URL'];
  final provisionKey = Platform.environment['FLORA_LIVE_PROVISION_KEY'];

  test('a fresh phone claims a gateway against the real server', () async {
    if (baseUrl == null || provisionKey == null) {
      markTestSkipped('FLORA_LIVE_URL and FLORA_LIVE_PROVISION_KEY unset');
      return;
    }

    // ---- 1. Act as the provisioner: register an aggregator ----
    final aggregatorSeed = List<int>.generate(32, (index) => (index * 3 + 11) % 256);
    final aggregatorPublic = await _publicKeyFor(aggregatorSeed);
    final deviceId = await Canonical.deviceId(aggregatorPublic);
    expect(deviceId.length, Protocol.gatewayIdHexLength);

    final deviceToken = _randomHex(32);
    final claimToken = _randomHex(32);

    final admin = Dio(BaseOptions(baseUrl: baseUrl));
    final register = await admin.post<dynamic>(
      '/provision/register',
      options: Options(headers: {
        'Authorization': 'Bearer $provisionKey',
        'Content-Type': 'application/json',
      }),
      data: jsonEncode({
        'device_id': deviceId,
        'pubkey': Canonical.hex(aggregatorPublic),
        'token_hash': Canonical.hex(await _sha256(Canonical.hexDecode(deviceToken)!)),
        'claim_hash': Canonical.hex(await _sha256(Canonical.hexDecode(claimToken)!)),
        'hw': 'pico_w',
        'fw_ver': '0.1.0',
        'label': 'dart-live-test',
      }),
    );
    expect(register.statusCode, 201, reason: 'register: ${register.data}');

    // ---- 2. Act as the app: sign the claim with its own code ----
    final api = ApiClient(baseUrl: baseUrl);
    final sessions = SessionStore(
      api: api,
      // A working in-memory store, so the test does not need a keystore.
      storage: _MemoryStorage(),
    );
    final cloud = CloudRepository(api: api, sessions: sessions);

    final phoneSeed = List<int>.generate(32, (index) => (index * 5 + 3) % 256);
    final phonePublic = await _publicKeyFor(phoneSeed);
    final keypair = _FakeKeypair(seed: phoneSeed, publicKey: phonePublic);

    final payload = QrPayload.parse(
      'flora://pair?v=1&id=$deviceId&ct=$claimToken&u=0202020202020202',
    );

    final result = await cloud.claim(payload: payload, keypair: keypair);
    expect(result.gatewayId, deviceId);
    expect(result.accountCreated, isTrue, reason: 'the first claim creates the account');

    // ---- 3. The session works for authenticated reads ----
    final account = await cloud.account();
    expect(account.gateways.length, 1);
    expect(account.gateways.first.id, deviceId);
    expect(account.gateways.first.label, 'dart-live-test');

    // ---- 4. The same key signs in again with a challenge ----
    final signedIn = await cloud.signIn(keypair);
    expect(signedIn, isTrue);
    final afterSignIn = await cloud.account();
    expect(afterSignIn.id, account.id, reason: 'the same key reaches the same account');

    // ---- 5. A rename reaches the server and comes back ----
    final renamed = await cloud.renameGateway(deviceId, 'plot-dart');
    expect(renamed.label, 'plot-dart');
    final refetched = await cloud.account();
    expect(refetched.gateways.first.label, 'plot-dart');

    // ---- 6. A signed command is accepted and queued ----
    final command = await cloud.sendCommand(
      gatewayId: deviceId,
      nodeAddr: 1,
      kind: Protocol.kindSetValve,
      payload: Canonical.valvePayload(open: true, durationSeconds: 300),
      keypair: keypair,
    );
    expect(command.status, 'pending');
    expect(command.nodeAddr, 1);

    // ---- 7. The same command signed by a different key is refused ----
    final stranger = _FakeKeypair(
      seed: List<int>.generate(32, (index) => (index * 9 + 7) % 256),
      publicKey: await _publicKeyFor(List<int>.generate(32, (index) => (index * 9 + 7) % 256)),
    );
    await expectLater(
      cloud.sendCommand(
        gatewayId: deviceId,
        nodeAddr: 1,
        kind: Protocol.kindSetValve,
        payload: Canonical.valvePayload(open: true, durationSeconds: 300),
        keypair: stranger,
      ),
      throwsA(isA<ApiFailure>()),
      reason: 'a key outside the account must not queue a command',
    );

    // ---- 8. An invite lets a second phone join ----
    final offer = await cloud.createInvite();
    expect(offer.payload, startsWith('flora://invite?v=1&a='));

    final secondSeed = List<int>.generate(32, (index) => (index * 7 + 5) % 256);
    final secondPublic = await _publicKeyFor(secondSeed);
    final secondApi = ApiClient(baseUrl: baseUrl);
    final secondCloud = CloudRepository(
      api: secondApi,
      sessions: SessionStore(api: secondApi, storage: _MemoryStorage()),
    );
    await secondCloud.redeemInvite(
      inviteToken: offer.token,
      keypair: _FakeKeypair(seed: secondSeed, publicKey: secondPublic),
    );
    final secondView = await secondCloud.account();
    expect(secondView.id, account.id, reason: 'the second phone joins the same account');
    expect(secondView.gateways.length, 1);
  }, timeout: const Timeout(Duration(minutes: 2)));
}

/// A keypair backed by raw bytes rather than the platform keystore.
///
/// The keystore is unavailable in a test environment, and the point here is the
/// signing, not the storage.
class _FakeKeypair implements AppKeypair {
  _FakeKeypair({required this.seed, required List<int> publicKey})
      : publicKey = Uint8List.fromList(publicKey);

  final List<int> seed;

  @override
  final Uint8List publicKey;

  @override
  SimpleKeyPair get keyPair => throw UnimplementedError('raw bytes only');

  @override
  String get publicKeyHex => Canonical.hex(publicKey);

  @override
  Future<Uint8List> sign(List<int> message) async {
    return _signWith(seed, message);
  }

  @override
  Future<String> derivedDeviceId() => Canonical.deviceId(publicKey);
}

/// An in-memory secret store, so the test needs no keystore.
class _MemoryStorage implements FlutterSecureStorage {
  final _values = <String, String>{};

  @override
  dynamic noSuchMethod(Invocation invocation) => throw UnimplementedError();

  @override
  Future<void> write({required String key, required String? value, dynamic iOptions, dynamic aOptions, dynamic lOptions, dynamic webOptions, dynamic mOptions, dynamic wOptions}) async {
    if (value == null) {
      _values.remove(key);
    } else {
      _values[key] = value;
    }
  }

  @override
  Future<String?> read({required String key, dynamic iOptions, dynamic aOptions, dynamic lOptions, dynamic webOptions, dynamic mOptions, dynamic wOptions}) async {
    return _values[key];
  }

  @override
  Future<void> delete({required String key, dynamic iOptions, dynamic aOptions, dynamic lOptions, dynamic webOptions, dynamic mOptions, dynamic wOptions}) async {
    _values.remove(key);
  }
}

/// Ed25519 signing, matching what the app does.
Future<Uint8List> _signWith(List<int> seed, List<int> message) async {
  final keyPair = await _ed25519.newKeyPairFromSeed(seed);
  final signature = await _ed25519.sign(message, keyPair: keyPair);
  return Uint8List.fromList(signature.bytes);
}

Future<Uint8List> _publicKeyFor(List<int> seed) async {
  final keyPair = await _ed25519.newKeyPairFromSeed(seed);
  final publicKey = await keyPair.extractPublicKey();
  return Uint8List.fromList(publicKey.bytes);
}

Future<Uint8List> _sha256(List<int> bytes) async {
  final digest = await _sha256Algorithm.hash(bytes);
  return Uint8List.fromList(digest.bytes);
}

String _randomHex(int byteCount) {
  final random = Random.secure();
  return Canonical.hex(
    List<int>.generate(byteCount, (_) => random.nextInt(256)),
  );
}

final _ed25519 = Ed25519();
final _sha256Algorithm = Sha256();
