import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flora_app/data/auth/keypair.dart';
import 'package:flora_app/data/auth/session.dart';
import 'package:flora_app/data/api/api_client.dart';
import 'package:flora_app/data/pairing/qr_payload.dart';

/// A keystore that fails the way a real one does when the platform plugin is
/// missing or the device's keystore is unavailable.
class _BrokenStorage implements FlutterSecureStorage {
  _BrokenStorage({this.failOn = 'read'});

  final String failOn;

  @override
  dynamic noSuchMethod(Invocation invocation) => throw UnimplementedError();

  @override
  Future<String?> read({required String key, dynamic iOptions, dynamic aOptions, dynamic lOptions, dynamic webOptions, dynamic mOptions, dynamic wOptions}) async {
    if (failOn == 'read') throw Exception('MissingPluginException(no implementation found)');
    return null;
  }

  @override
  Future<void> write({required String key, required String? value, dynamic iOptions, dynamic aOptions, dynamic lOptions, dynamic webOptions, dynamic mOptions, dynamic wOptions}) async {
    if (failOn == 'write') throw Exception('MissingPluginException(no implementation found)');
  }

  @override
  Future<void> delete({required String key, dynamic iOptions, dynamic aOptions, dynamic lOptions, dynamic webOptions, dynamic mOptions, dynamic wOptions}) async {}
}

void main() {
  group('an unreadable keystore', () {
    test('is reported, not treated as a fresh install', () async {
      // The distinction that matters: a key that exists but cannot be read must
      // not be handled like no key at all, or the app mints a second identity
      // and strands the first account.
      final store = KeypairStore(storage: _BrokenStorage());

      await expectLater(
        store.load(),
        throwsA(isA<KeystoreUnavailable>()),
      );
      await expectLater(
        store.loadOrCreate(),
        throwsA(isA<KeystoreUnavailable>()),
      );
    });

    test('explains itself in words a person can act on', () async {
      final store = KeypairStore(storage: _BrokenStorage());
      try {
        await store.load();
        fail('expected a KeystoreUnavailable');
      } on KeystoreUnavailable catch (error) {
        // Not the raw platform string: the user needs to know what to do.
        expect(error.message, isNot(contains('MissingPluginException')));
        expect(error.message.toLowerCase(), contains('keystore'));
      }
    });

    test('a write failure during creation is reported too', () async {
      // Creating an identity that cannot be persisted would produce a key that
      // changes on every launch, so each launch would be a new account.
      final store = KeypairStore(storage: _BrokenStorage(failOn: 'write'));
      await expectLater(
        store.loadOrCreate(),
        throwsA(isA<KeystoreUnavailable>()),
      );
    });
  });

  group('an unreadable session', () {
    test('degrades to signed out rather than failing', () async {
      // Unlike the keypair, a lost session costs nothing: the key is the
      // identity, so signing in again reaches the same account. This must not
      // be an error path that blocks the app.
      final api = ApiClient(baseUrl: 'http://127.0.0.1:1');
      final sessions = SessionStore(api: api, storage: _BrokenStorage());
      expect(await sessions.load(), isNull);
      expect(sessions.current, isNull);
    });

    test('a failed write does not break the live session', () async {
      final api = ApiClient(baseUrl: 'http://127.0.0.1:1');
      final sessions = SessionStore(api: api, storage: _BrokenStorage(failOn: 'write'));
      // Should complete without throwing: the token is already in memory and
      // the current run works.
      await sessions.save(
        Session(
          accessToken: 'a',
          refreshToken: 'b',
          accountId: 'c',
          expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
        ),
      );
      expect(sessions.current, isNotNull);
    });
  });
}
