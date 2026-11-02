import 'dart:async';
import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../api/api_client.dart';

/// The signed-in session: access token, refresh token, and account id.
///
/// The access token lives in memory because it is short-lived; the refresh
/// token is persisted so the app does not demand a signature on every launch,
/// which would mean touching the keystore each time.
class Session {
  Session({
    required this.accessToken,
    required this.refreshToken,
    required this.accountId,
    required this.expiresAt,
  });

  String accessToken;
  String refreshToken;
  final String accountId;
  DateTime expiresAt;

  /// Whether the access token is close enough to expiry to refresh first.
  ///
  /// A minute of slack stops a request racing the expiry.
  bool get needsRefresh =>
      DateTime.now().toUtc().isAfter(expiresAt.subtract(const Duration(minutes: 1)));

  Map<String, dynamic> toJson() => {
        'access_token': accessToken,
        'refresh_token': refreshToken,
        'account_id': accountId,
        'expires_at': expiresAt.toIso8601String(),
      };

  static Session? fromJson(Map<String, dynamic> json) {
    final access = json['access_token'];
    final refresh = json['refresh_token'];
    final account = json['account_id'];
    final expires = json['expires_at'];
    if (access is! String || refresh is! String || account is! String || expires is! String) {
      return null;
    }
    final parsedExpiry = DateTime.tryParse(expires);
    if (parsedExpiry == null) return null;
    return Session(
      accessToken: access,
      refreshToken: refresh,
      accountId: account,
      expiresAt: parsedExpiry.toUtc(),
    );
  }
}

/// Persists the session and refreshes it when needed.
class SessionStore {
  SessionStore({
    required ApiClient api,
    FlutterSecureStorage? storage,
  })  : _api = api,
        _storage = storage ?? const FlutterSecureStorage();



  static const _sessionKey = 'flora.session';

  final ApiClient _api;
  final FlutterSecureStorage _storage;

  Session? _current;

  /// The live session, or null when this device has never paired.
  Session? get current => _current;

  /// Load a stored session and point the API client at it.
  Future<Session?> load() async {
    try {
      final raw = await _storage.read(key: _sessionKey);
      if (raw == null || raw.isEmpty) return null;
      final decoded = jsonDecode(raw);
      if (decoded is! Map<String, dynamic>) return null;
      final session = Session.fromJson(decoded);
      if (session == null) {
        // A malformed session is worse than none: it would make every request
        // fail with 401. Drop it so the app starts at the pairing screen.
        await clear();
        return null;
      }
      _current = session;
      _api.setAccessToken(session.accessToken);
      return session;
    } on FormatException {
      await clear();
      return null;
    } catch (_) {
      // Unreadable storage degrades to "not signed in" rather than an error.
      // Unlike the keypair, this loses nothing: the key is the identity, so
      // signing in again reaches the same account.
      return null;
    }
  }

  /// Store a session returned by pairing or signing in.
  Future<void> save(Session session) async {
    _current = session;
    _api.setAccessToken(session.accessToken);
    await _persist(session);
  }

  /// Exchange the refresh token for a new pair.
  ///
  /// Returns false when the refresh token is no longer valid, which means the
  /// user must sign in again with the recovery phrase.
  Future<bool> refresh() async {
    final session = _current;
    if (session == null) return false;
    try {
      final body = await _api.postJson(
        '/auth/refresh',
        body: {'refresh_token': session.refreshToken},
      );
      final refreshed = Session(
        accessToken: body['access_token'] as String,
        // The server rotates: the old refresh token is consumed.
        refreshToken: body['refresh_token'] as String,
        accountId: body['account_id'] as String,
        expiresAt: DateTime.now().toUtc().add(
              Duration(seconds: (body['expires_in'] as num?)?.toInt() ?? 3600),
            ),
      );
      await save(refreshed);
      return true;
    } on ApiFailure {
      // Any failure here means the stored session is unusable; clear it so the
      // app does not loop on a dead token.
      await clear();
      return false;
    }
  }

  /// Refresh only if the token is near expiry.
  Future<void> ensureFresh() async {
    final session = _current;
    if (session == null) return;
    if (session.needsRefresh) {
      await refresh();
    }
  }

  /// Forget the session, leaving the keypair in place.
  ///
  /// Deliberately does not touch the keypair: the device keeps its identity, so
  /// signing in again uses the same key and reaches the same account.
  Future<void> clear() async {
    _current = null;
    _api.setAccessToken(null);
    try {
      await _storage.delete(key: _sessionKey);
    } catch (_) {
      // Already forgotten in memory, which is what matters for sign-out. A
      // storage failure here only means a stale row lingers, and the next
      // launch treats an unusable row as no session.
    }
  }

  Future<void> _persist(Session session) async {
    try {
      await _storage.write(key: _sessionKey, value: jsonEncode(session.toJson()));
    } catch (_) {
      // The session is live in memory and the API client already holds the
      // token, so the current run works. Only the next launch is affected, and
      // it will ask for a signature instead of failing.
    }
  }
}
