import '../../core/protocol.dart';
import '../auth/keypair.dart';
import '../auth/session.dart';
import '../models/models.dart';
import '../pairing/qr_payload.dart';
import '../protocol/canonical.dart';
import 'api_client.dart';

/// Every cloud call the app makes, in one place.
///
/// Screens never touch [ApiClient] directly, so a change in the wire contract
/// is one edit rather than a search, and the signing rules cannot be forgotten
/// by a new screen.
class CloudRepository {
  CloudRepository({required ApiClient api, required SessionStore sessions})
      : _api = api,
        _sessions = sessions;

  final ApiClient _api;
  final SessionStore _sessions;

  /// Whether the app currently holds a session.
  bool get isSignedIn => _sessions.current != null;

  /// The signed-in account id, or null.
  String? get accountId => _sessions.current?.accountId;

  /// Load a stored session at startup.
  Future<Session?> restore() async {
    final session = await _sessions.load();
    if (session == null) return null;
    // A stored token may have expired while the app was closed.
    await _sessions.ensureFresh();
    return _sessions.current;
  }

  /// Claim a gateway with a scanned code.
  ///
  /// The signature covers the device id as text, a separator, the raw claim
  /// token, and the nonce, in that order. Signing the wrong bytes here is the
  /// failure that would look like "the code is not recognised".
  Future<ClaimResult> claim({
    required QrPayload payload,
    required AppKeypair keypair,
    String? label,
  }) async {
    final nonce = freshNonce();
    final message = Canonical.pairingClaim(
      deviceId: payload.deviceId,
      claimToken: payload.claimTokenBytes,
      nonce: nonce,
    );
    final signature = await keypair.sign(message);

    final body = await _api.postJson('/pair/claim', body: {
      'device_id': payload.deviceId,
      'claim_token': payload.claimToken,
      'app_pubkey': keypair.publicKeyHex,
      'nonce': Canonical.hex(nonce),
      'signature': Canonical.hex(signature),
      if (label != null && label.trim().isNotEmpty) 'label': label.trim(),
    });

    final session = Session(
      accessToken: body['access_token'] as String,
      refreshToken: body['refresh_token'] as String,
      accountId: body['account_id'] as String,
      expiresAt: DateTime.now().toUtc().add(
            Duration(seconds: (body['expires_in'] as num?)?.toInt() ?? 3600),
          ),
    );
    await _sessions.save(session);

    return ClaimResult(
      gatewayId: body['gateway_id'] as String? ?? payload.deviceId,
      accountCreated: body['account_created'] as bool? ?? false,
    );
  }

  /// Sign in with the key already on this device.
  ///
  /// Used after a restore or when the session expired but the keypair is still
  /// present, which is the common case: the phone keeps its identity.
  Future<bool> signIn(AppKeypair keypair) async {
    final challenge = await _api.postJson(
      '/auth/challenge',
      body: {'app_pubkey': keypair.publicKeyHex},
    );
    final nonce = challenge['nonce'] as String;
    final nonceBytes = Canonical.hexDecode(nonce);
    if (nonceBytes == null) {
      throw const ApiFailure('The server sent an unreadable challenge.');
    }

    final signature = await keypair.sign(
      Canonical.auth(publicKey: keypair.publicKey, nonce: nonceBytes),
    );

    final body = await _api.postJson('/auth/verify', body: {
      'app_pubkey': keypair.publicKeyHex,
      'nonce': nonce,
      'signature': Canonical.hex(signature),
    });

    await _sessions.save(
      Session(
        accessToken: body['access_token'] as String,
        refreshToken: body['refresh_token'] as String,
        accountId: body['account_id'] as String,
        expiresAt: DateTime.now().toUtc().add(
              Duration(seconds: (body['expires_in'] as num?)?.toInt() ?? 3600),
            ),
      ),
    );
    return true;
  }

  /// The account and its gateways.
  Future<Account> account() async {
    await _sessions.ensureFresh();
    final body = await _api.getJson('/account/me');
    return Account.fromJson(body);
  }

  /// Just the gateways, for a refresh that need not fetch the account.
  Future<List<Gateway>> gateways() async {
    await _sessions.ensureFresh();
    final list = await _api.getList('/account/gateways');
    return list
        .map((entry) => Gateway.fromJson(entry as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// The nodes a gateway has discovered.
  Future<List<Node>> nodes(String gatewayId) async {
    await _sessions.ensureFresh();
    final list = await _api.getList('/gateways/$gatewayId/nodes');
    return list
        .map((entry) => Node.fromJson(entry as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// The newest reading per node.
  Future<List<Reading>> latestReadings(String gatewayId) async {
    await _sessions.ensureFresh();
    final list = await _api.getList('/gateways/$gatewayId/readings/latest');
    return list
        .map((entry) => Reading.fromJson(entry as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// Readings over a window, optionally for one node and one metric.
  ///
  /// [since] and [until] are sent as epoch seconds, which the server accepts
  /// alongside RFC 3339.
  Future<List<Reading>> history(
    String gatewayId, {
    required DateTime since,
    DateTime? until,
    String? nodeUuid,
    String? metric,
    int? limit,
  }) async {
    await _sessions.ensureFresh();
    final list = await _api.getList(
      '/gateways/$gatewayId/readings',
      query: {
        'from': '${since.toUtc().millisecondsSinceEpoch ~/ 1000}',
        if (until != null) 'to': '${until.toUtc().millisecondsSinceEpoch ~/ 1000}',
        if (nodeUuid != null) 'node_uuid': nodeUuid,
        if (metric != null) 'metric': metric,
        if (limit != null) 'limit': limit,
      },
    );
    return list
        .map((entry) => Reading.fromJson(entry as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// Send a signed manual command to a gateway.
  ///
  /// The signature covers the canonical encoding, so the server can reject a
  /// tampered command early and the aggregator can reject it independently.
  /// Returning the queued id lets the UI track it to a conclusion.
  Future<CommandStatus> sendCommand({
    required String gatewayId,
    required int nodeAddr,
    required int kind,
    required List<int> payload,
    required AppKeypair keypair,
  }) async {
    await _sessions.ensureFresh();

    final gatewayBytes = Canonical.hexDecode(gatewayId);
    if (gatewayBytes == null || gatewayBytes.length != Protocol.gatewayIdLength) {
      throw ApiFailure.local('That plot has an unrecognised identifier.');
    }

    final nonce = _nextNonce();
    final timestamp = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    final signature = await keypair.sign(
      Canonical.command(
        kind: kind,
        gatewayId: gatewayBytes,
        nodeAddr: nodeAddr,
        nonce: nonce,
        timestamp: timestamp,
        payload: payload,
      ),
    );

    final body = await _api.postJson('/gateways/$gatewayId/commands', body: {
      'node_addr': nodeAddr,
      'kind': Protocol.kindName(kind),
      'payload': Canonical.hex(payload),
      'app_pubkey': keypair.publicKeyHex,
      'nonce': nonce,
      'ts': timestamp,
      'signature': Canonical.hex(signature),
    });

    return CommandStatus.fromJson(body);
  }

  /// The recent command history for a gateway.
  Future<List<CommandStatus>> commands(String gatewayId) async {
    await _sessions.ensureFresh();
    final list = await _api.getList('/gateways/$gatewayId/commands');
    return list
        .map((entry) => CommandStatus.fromJson(entry as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// Rename a gateway.
  Future<Gateway> renameGateway(String gatewayId, String? label) async {
    await _sessions.ensureFresh();
    final body = await _api.patchJson(
      '/gateways/$gatewayId/label',
      body: {'label': label},
    );
    return Gateway.fromJson(body);
  }

  /// Rename a node.
  Future<void> renameNode(String gatewayId, String nodeUuid, String? label) async {
    await _sessions.ensureFresh();
    await _api.patchJson(
      '/gateways/$gatewayId/nodes/$nodeUuid/label',
      body: {'label': label},
    );
  }

  /// Retire a gateway the farmer no longer uses.
  Future<void> retireGateway(String gatewayId) async {
    await _sessions.ensureFresh();
    await _api.postEmpty('/gateways/$gatewayId/retire');
  }

  /// Fleet health across the account.
  Future<Map<String, dynamic>> fleetHealth() async {
    await _sessions.ensureFresh();
    return _api.getJson('/account/reports/fleet-health');
  }

  /// Mint an invite for another phone to join this account.
  ///
  /// The token is returned once and only its hash is stored, so a lost token
  /// cannot be recovered: mint another.
  Future<InviteOffer> createInvite() async {
    await _sessions.ensureFresh();
    final body = await _api.postJson('/account/invite');
    return InviteOffer(
      payload: body['payload'] as String,
      token: body['token'] as String,
      expiresAt: DateTime.tryParse(body['expires_at'] as String? ?? '')?.toUtc() ??
          DateTime.now().toUtc(),
    );
  }

  /// Join an account from an invite, using the app key on this device.
  Future<void> redeemInvite({
    required String inviteToken,
    required AppKeypair keypair,
  }) async {
    final tokenBytes = Canonical.hexDecode(inviteToken);
    if (tokenBytes == null || tokenBytes.length != Protocol.tokenLength) {
      throw ApiFailure.local('That invite code is damaged. Ask for a new one.');
    }

    final nonce = freshNonce();
    final signature = await keypair.sign(
      inviteMessage(
        publicKey: keypair.publicKey,
        inviteToken: tokenBytes,
        nonce: nonce,
      ),
    );

    final body = await _api.postJson('/pair/invite', body: {
      'invite_token': inviteToken,
      'app_pubkey': keypair.publicKeyHex,
      'nonce': Canonical.hex(nonce),
      'signature': Canonical.hex(signature),
    });

    await _sessions.save(
      Session(
        accessToken: body['access_token'] as String,
        refreshToken: body['refresh_token'] as String,
        accountId: body['account_id'] as String,
        expiresAt: DateTime.now().toUtc().add(
              Duration(seconds: (body['expires_in'] as num?)?.toInt() ?? 3600),
            ),
      ),
    );
  }

  /// Sign out on this device, keeping the keypair.
  Future<void> signOut() => _sessions.clear();

  /// A monotonically increasing nonce.
  ///
  /// The server rejects a repeated nonce, and the aggregator keeps a rolling
  /// cache, so a counter seeded from the clock is enough and is cheaper than
  /// asking the server for one per command.
  static int _nonceCounter = 0;
  int _nextNonce() {
    _nonceCounter = (_nonceCounter + 1) & 0x7FFFFFFF;
    final seconds = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    // Combine so the value is unique across restarts as well as within a run.
    return ((seconds & 0xFFFF) << 15 | _nonceCounter) & 0xFFFFFFFF;
  }
}

/// The message a phone signs to accept an invite.
///
/// Domain-separated from claiming and from signing in, so a signature made for
/// one flow cannot be replayed into another. Mirrors `invite_message` on the
/// server.
List<int> inviteMessage({
  required List<int> publicKey,
  required List<int> inviteToken,
  required List<int> nonce,
}) {
  return [
    ...'flora-invite-v1'.codeUnits,
    ...publicKey,
    ...inviteToken,
    ...nonce,
  ];
}

/// An invite to show another phone.
class InviteOffer {
  const InviteOffer({
    required this.payload,
    required this.token,
    required this.expiresAt,
  });

  /// What to encode in a QR.
  final String payload;

  /// The raw token, shown once.
  final String token;

  final DateTime expiresAt;

  /// Minutes left before it stops working.
  int get minutesRemaining {
    final remaining = expiresAt.difference(DateTime.now().toUtc()).inMinutes;
    return remaining < 0 ? 0 : remaining;
  }
}

/// What a successful claim produced.
class ClaimResult {
  const ClaimResult({required this.gatewayId, required this.accountCreated});

  final String gatewayId;

  /// True when this claim created the account, which is when the app should
  /// offer to save a recovery phrase.
  final bool accountCreated;
}
