import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/config.dart';
import '../data/api/api_client.dart';
import '../data/api/cloud_repository.dart';
import '../data/auth/keypair.dart';
import '../data/auth/mnemonic.dart';
import '../data/auth/session.dart';
import '../data/models/models.dart';
import '../data/ws/event_stream.dart';

/// The HTTP client, configured once.
final apiClientProvider = Provider<ApiClient>((ref) {
  return ApiClient(baseUrl: AppConfig.apiBaseUrl);
});

/// Session storage.
final sessionStoreProvider = Provider<SessionStore>((ref) {
  return SessionStore(api: ref.watch(apiClientProvider));
});

/// The keypair, loaded lazily.
///
/// Deliberately not created at startup: the app must be usable before any
/// device is paired, and generating an identity the user never asked for is
/// the kind of thing that makes a "no account needed" promise untrue.
final keypairProvider = FutureProvider<AppKeypair?>((ref) async {
  return KeypairStore().load();
});

/// Every cloud call.
final cloudProvider = Provider<CloudRepository>((ref) {
  return CloudRepository(
    api: ref.watch(apiClientProvider),
    sessions: ref.watch(sessionStoreProvider),
  );
});

/// The signed-in account, or null when this device has never paired.
///
/// Nullable on purpose: the shell renders an empty state rather than a login
/// wall, because a farmer who has not scanned a code yet is a normal user.
class AccountState {
  const AccountState({
    this.account,
    this.loading = false,
    this.error,
    this.restored = false,
  });

  final Account? account;
  final bool loading;
  final String? error;

  /// Whether the startup restore has finished, so the UI can avoid flashing an
  /// empty state before it knows.
  final bool restored;

  bool get isSignedIn => account != null;

  AccountState copyWith({
    Account? account,
    bool? loading,
    String? error,
    bool? restored,
    bool clearAccount = false,
    bool clearError = false,
  }) {
    return AccountState(
      account: clearAccount ? null : (account ?? this.account),
      loading: loading ?? this.loading,
      error: clearError ? null : (error ?? this.error),
      restored: restored ?? this.restored,
    );
  }
}

class AccountNotifier extends Notifier<AccountState> {
  @override
  AccountState build() {
    // Kick off the restore, but do not block the first frame on it.
    unawaited(_restore());
    return const AccountState(loading: true);
  }

  CloudRepository get _cloud => ref.read(cloudProvider);

  Future<void> _restore() async {
    try {
      final session = await _cloud.restore();
      notifySessionChanged(ref);
      if (session == null) {
        state = state.copyWith(loading: false, restored: true, clearAccount: true);
        return;
      }
      final account = await _cloud.account();
      state = AccountState(account: account, restored: true);
    } on ApiFailure catch (failure) {
      // A failed restore is not fatal: the shell still works, and the user can
      // pair again. Report it without blocking anything.
      state = state.copyWith(loading: false, restored: true, error: failure.message);
    } catch (error) {
      state = state.copyWith(loading: false, restored: true, error: '$error');
    }
  }

  /// Reload the account and its gateways.
  Future<void> refresh() async {
    // A refresh may have rotated the access token.
    notifySessionChanged(ref);
    if (!_cloud.isSignedIn) {
      await _restore();
      return;
    }
    state = state.copyWith(loading: true, clearError: true);
    try {
      final account = await _cloud.account();
      state = AccountState(account: account, restored: true);
    } on ApiFailure catch (failure) {
      state = state.copyWith(loading: false, error: failure.message);
    }
  }

  /// Apply a claim result, so the UI updates without a round trip.
  Future<void> onClaimed() async {
    notifySessionChanged(ref);
    state = state.copyWith(loading: true, clearError: true);
    try {
      final account = await _cloud.account();
      state = AccountState(account: account, restored: true);
    } on ApiFailure catch (failure) {
      state = state.copyWith(loading: false, error: failure.message);
    }
  }

  /// Replace the local name of a gateway after a successful rename.
  void applyLabel(String gatewayId, String? label) {
    final account = state.account;
    if (account == null) return;
    final updated = account.gateways
        .map((gateway) => gateway.id == gatewayId
            ? Gateway(
                id: gateway.id,
                status: gateway.status,
                label: label,
                firmwareVersion: gateway.firmwareVersion,
                lastSeen: gateway.lastSeen,
                claimedAt: gateway.claimedAt,
              )
            : gateway)
        .toList(growable: false);
    state = state.copyWith(
      account: Account(
        id: account.id,
        createdAt: account.createdAt,
        gateways: updated,
      ),
    );
  }

  Future<void> signOut() async {
    await _cloud.signOut();
    notifySessionChanged(ref);
    state = const AccountState(restored: true);
  }
}

final accountProvider =
    NotifierProvider<AccountNotifier, AccountState>(AccountNotifier.new);

/// The gateways under the signed-in account, or an empty list.
final gatewaysProvider = Provider<List<Gateway>>((ref) {
  return ref.watch(accountProvider).account?.gateways ?? const [];
});

/// Live readings for a gateway, seeded by a fetch and updated by the stream.
class GatewayTelemetry {
  const GatewayTelemetry({
    this.readings = const {},
    this.nodes = const [],
    this.loading = false,
    this.error,
  });

  /// Newest reading per node uuid.
  final Map<String, Reading> readings;

  final List<Node> nodes;
  final bool loading;
  final String? error;

  Reading? readingFor(String nodeUuid) => readings[nodeUuid];

  GatewayTelemetry copyWith({
    Map<String, Reading>? readings,
    List<Node>? nodes,
    bool? loading,
    String? error,
    bool clearError = false,
  }) {
    return GatewayTelemetry(
      readings: readings ?? this.readings,
      nodes: nodes ?? this.nodes,
      loading: loading ?? this.loading,
      error: clearError ? null : (error ?? this.error),
    );
  }
}

class TelemetryNotifier extends Notifier<GatewayTelemetry> {
  TelemetryNotifier(this.gatewayId);

  /// The gateway this instance tracks. The family factory passes the key, so a
  /// per-gateway notifier does not need to look it up.
  final String gatewayId;

  StreamSubscription<StreamEvent>? _subscription;

  @override
  GatewayTelemetry build() {
    // Fetch once, then let the stream keep it current.
    unawaited(_load(gatewayId));

    // The stream is absent while signed out, so subscribing is conditional.
    final stream = ref.watch(accountStreamProvider);
    _subscription = stream?.events.listen((event) {
      if (event is TelemetryEvent && event.gatewayId == gatewayId) {
        _merge(event.readings);
      }
      if (event is LaggedEvent) {
        // Local state may be stale after a gap, so refetch rather than trust it.
        unawaited(_load(gatewayId));
      }
    });

    ref.onDispose(() => _subscription?.cancel());
    return const GatewayTelemetry(loading: true);
  }

  Future<void> _load(String gatewayId) async {
    final cloud = ref.read(cloudProvider);
    try {
      final results = await Future.wait([
        cloud.nodes(gatewayId),
        cloud.latestReadings(gatewayId),
      ]);
      final nodes = results[0] as List<Node>;
      final readings = results[1] as List<Reading>;
      state = GatewayTelemetry(
        nodes: nodes,
        readings: {for (final reading in readings) reading.nodeUuid: reading},
      );
    } on ApiFailure catch (failure) {
      state = state.copyWith(loading: false, error: failure.message);
    }
  }

  Future<void> refresh() async {
    state = state.copyWith(loading: true, clearError: true);
    await _load(gatewayId);
  }

  void _merge(List<Reading> incoming) {
    final merged = Map<String, Reading>.from(state.readings);
    for (final reading in incoming) {
      final existing = merged[reading.nodeUuid];
      // The stream carries no timestamp, so a reading is only replaced when it
      // is plausibly newer: the sequence is monotonic per node, and a missing
      // sequence means the stream is the freshest source available.
      if (existing == null ||
          reading.seq == null ||
          existing.seq == null ||
          reading.seq! >= existing.seq!) {
        merged[reading.nodeUuid] = reading;
      }
    }
    state = state.copyWith(readings: merged);
  }
}

final telemetryProvider =
    NotifierProvider.family<TelemetryNotifier, GatewayTelemetry, String>(
  TelemetryNotifier.new,
);

/// The account-wide event stream, or null when there is nothing to stream.
///
/// One connection serves every screen, rather than one per gateway, because the
/// platform's idle rule counts connections and a single socket is cheaper.
///
/// Returns null while signed out. An earlier version created the socket
/// unconditionally, which meant it connected with an empty token before
/// sign-in, was closed by the server, and never came back because nothing
/// re-evaluated it. Keying on the account fixes that: signing in produces a new
/// stream, signing out disposes it.
final accountStreamProvider = Provider<EventStream?>((ref) {
  final account = ref.watch(accountProvider);
  if (!account.isSignedIn) return null;

  // Depend on the access token so a refresh replaces the socket rather than
  // leaving one authenticated with an expired token.
  final token = ref.watch(accessTokenProvider);
  if (token == null || token.isEmpty) return null;

  final stream = EventStream(
    url: '${AppConfig.streamBaseUrl}/account/stream',
    accessToken: token,
  );
  stream.connect();
  ref.onDispose(() => unawaited(stream.dispose()));
  return stream;
});

/// Bumped whenever a session is saved or cleared.
///
/// The store is a plain object, so it cannot notify on its own; this is the
/// observable signal that its contents changed, which is what lets the stream
/// and the signed-in flag update without a manual refresh.
class SessionRevision extends Notifier<int> {
  @override
  int build() => 0;

  void bump() => state = state + 1;
}

final sessionRevisionProvider =
    NotifierProvider<SessionRevision, int>(SessionRevision.new);

/// The session as a reactive value.
final sessionProvider = Provider<Session?>((ref) {
  ref.watch(sessionRevisionProvider);
  return ref.watch(sessionStoreProvider).current;
});

/// The current access token, or null while signed out.
final accessTokenProvider = Provider<String?>((ref) {
  return ref.watch(sessionProvider)?.accessToken;
});

/// Tell dependents that the session changed.
///
/// Called after every save, refresh, and sign-out so the stream reconnects with
/// a valid token rather than holding one that has expired.
void notifySessionChanged(Ref ref) {
  ref.read(sessionRevisionProvider.notifier).bump();
}

/// Connection state, for the live indicator.
///
/// Reports `stopped` while signed out rather than leaving the indicator
/// spinning, because there is nothing to connect to yet.
final streamStatusProvider = StreamProvider<StreamStatus>((ref) {
  final stream = ref.watch(accountStreamProvider);
  if (stream == null) return Stream.value(StreamStatus.stopped);
  return stream.status;
});

/// The recovery phrase for the current keypair.
///
/// Shown only by an explicit request, because it is the account itself.
final recoveryPhraseProvider = FutureProvider<String?>((ref) async {
  final keypair = await ref.watch(keypairProvider.future);
  if (keypair == null) return null;
  final seed = await KeypairStore().exportSeed();
  if (seed == null) return null;
  return RecoveryPhrase.fromSeed(seed);
});
