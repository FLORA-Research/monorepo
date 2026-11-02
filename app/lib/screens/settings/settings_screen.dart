import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/config.dart';
import '../../core/format.dart';
import '../../core/theme.dart';
import '../../data/api/api_client.dart';
import '../../data/pairing/qr_payload.dart';
import '../../providers/providers.dart';
import '../../widgets/common.dart';
import '../home/rename_dialog.dart';
import '../recovery/restore_screen.dart';
import '../recovery/show_phrase_screen.dart';
import 'invite_screen.dart';
import 'join_screen.dart';

/// Settings, usable with or without an account.
///
/// Nothing here is gated behind pairing, because a farmer who has not scanned a
/// code yet should still be able to read the about screen and check the
/// connection.
class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final account = ref.watch(accountProvider);

    return PageBody(
      title: 'Settings',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _ConnectionCard(),
          const SizedBox(height: Gap.xl),
          const SectionHeading('ACCOUNT'),
          if (account.isSignedIn)
            _SignedInSection(accountId: account.account!.id)
          else
            _SignedOutSection(),
          const SizedBox(height: Gap.xl),
          const SectionHeading('ABOUT'),
          const _AboutCard(),
        ],
      ),
    );
  }
}

/// Whether the app can reach the cloud, with a way to test it.
class _ConnectionCard extends ConsumerStatefulWidget {
  @override
  ConsumerState<_ConnectionCard> createState() => _ConnectionCardState();
}

class _ConnectionCardState extends ConsumerState<_ConnectionCard> {
  bool _checking = false;
  String? _result;
  String? _storageResult;
  bool _ok = false;

  Future<void> _check() async {
    setState(() {
      _checking = true;
      _result = null;
      _storageResult = null;
    });

    // Storage first: it is local and instant, and it is the failure that makes
    // pairing impossible in a way no message from the server would explain.
    final storage = await SecureStorageProbe().probe();
    if (!mounted) return;
    setState(() => _storageResult = storage);

    try {
      // The liveness path deliberately does no database work, so this tests the
      // network path without measuring the database's mood.
      await ref.read(apiClientProvider).getJson('/uptime');
      if (!mounted) return;
      setState(() {
        _ok = true;
        _result = 'Reached the server.';
      });
    } on ApiFailure catch (failure) {
      if (!mounted) return;
      setState(() {
        _ok = false;
        _result = failure.message;
      });
    } finally {
      if (mounted) setState(() => _checking = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(Gap.lg),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.cloud_outlined, color: FloraColors.soil),
                const SizedBox(width: Gap.md),
                const Expanded(
                  child: Text(
                    'Self-check',
                    style: TextStyle(fontSize: 15, fontWeight: FontWeight.w700),
                  ),
                ),
                if (_result != null)
                  Icon(
                    _ok ? Icons.check_circle : Icons.error_outline,
                    color: _ok ? FloraColors.leaf : FloraColors.alarm,
                    size: 20,
                  ),
              ],
            ),
            const SizedBox(height: Gap.sm),
            Text(
              AppConfig.apiBaseUrl,
              style: const TextStyle(fontSize: 12, color: FloraColors.muted),
            ),
            if (!AppConfig.isEncrypted) ...[
              const SizedBox(height: Gap.sm),
              const Text(
                'This build talks to the server without encryption. That is only appropriate '
                'for local testing.',
                style: TextStyle(fontSize: 12, color: FloraColors.clay),
              ),
            ],
            if (_result != null) ...[
              const SizedBox(height: Gap.sm),
              Text(
                _result!,
                style: TextStyle(
                  fontSize: 13,
                  color: _ok ? FloraColors.ink : FloraColors.alarm,
                ),
              ),
            ],
            if (_storageResult != null) ...[
              const SizedBox(height: Gap.xs),
              Text(
                _storageResult!,
                style: const TextStyle(fontSize: 13, color: FloraColors.alarm),
              ),
            ],
            const SizedBox(height: Gap.md),
            OutlinedButton(
              onPressed: _checking ? null : _check,
              child: _checking
                  ? const SizedBox(
                      height: 18,
                      width: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Text('Run a self-check'),
            ),
          ],
        ),
      ),
    );
  }
}

/// Account actions when a device is paired.
class _SignedInSection extends ConsumerWidget {
  const _SignedInSection({required this.accountId});

  final String accountId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final gateways = ref.watch(gatewaysProvider);

    return Card(
      child: Column(
        children: [
          ListTile(
            leading: const Icon(Icons.fingerprint),
            title: const Text('This account'),
            subtitle: Text(
              // Shortened because a full identifier is not useful to read aloud.
              '${accountId.substring(0, 8)}… · ${gateways.length} plot'
              '${gateways.length == 1 ? "" : "s"}',
              style: const TextStyle(fontSize: 12),
            ),
          ),
          const Divider(height: 1),
          ListTile(
            leading: const Icon(Icons.person_add_alt),
            title: const Text('Invite another phone'),
            subtitle: const Text(
              'Let a second phone see and control this account',
              style: TextStyle(fontSize: 12),
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const InviteScreen()),
            ),
          ),
          const Divider(height: 1),
          ListTile(
            leading: const Icon(Icons.key_outlined),
            title: const Text('Recovery phrase'),
            subtitle: const Text(
              'Twelve words that restore this account',
              style: TextStyle(fontSize: 12),
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const ShowPhraseScreen()),
            ),
          ),
          const Divider(height: 1),
          for (final gateway in gateways) ...[
            ListTile(
              leading: const Icon(Icons.landscape_outlined),
              title: Text(gateway.displayName),
              subtitle: Text(
                gateway.isRetired ? 'Retired' : 'Seen ${Fmt.ago(gateway.lastSeen)}',
                style: const TextStyle(fontSize: 12),
              ),
              trailing: IconButton(
                tooltip: 'Rename',
                icon: const Icon(Icons.edit_outlined, size: 20),
                onPressed: () => renameGateway(context, ref, gateway),
              ),
            ),
            if (gateway != gateways.last) const Divider(height: 1),
          ],
          const Divider(height: 1),
          ListTile(
            leading: const Icon(Icons.logout, color: FloraColors.alarm),
            title: const Text(
              'Sign out on this phone',
              style: TextStyle(color: FloraColors.alarm),
            ),
            subtitle: const Text(
              'Removes the session. Your key stays, so you can sign back in or restore later.',
              style: TextStyle(fontSize: 12),
            ),
            onTap: () async {
              final confirmed = await confirmDestructive(
                context,
                title: 'Sign out?',
                body: 'This phone will stop showing your plots until you sign in again. '
                    'Nothing is deleted, and your recovery phrase still works.',
                confirmLabel: 'Sign out',
              );
              if (!confirmed) return;
              await ref.read(accountProvider.notifier).signOut();
            },
          ),
        ],
      ),
    );
  }
}

/// Account actions when nothing is paired.
class _SignedOutSection extends StatelessWidget {
  const _SignedOutSection();

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Column(
        children: [
          const ListTile(
            leading: Icon(Icons.info_outline),
            title: Text('No account on this phone'),
            subtitle: Text(
              'Everything else in this app works without one. An account is created '
              'the first time you scan a device code.',
              style: TextStyle(fontSize: 12),
            ),
          ),
          const Divider(height: 1),
          ListTile(
            leading: const Icon(Icons.qr_code_scanner),
            title: const Text('Join with a code'),
            subtitle: const Text(
              'For a second phone that was invited',
              style: TextStyle(fontSize: 12),
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const JoinScreen()),
            ),
          ),
          const Divider(height: 1),
          ListTile(
            leading: const Icon(Icons.restore),
            title: const Text('Restore from a recovery phrase'),
            subtitle: const Text(
              'For a new phone, or after reinstalling',
              style: TextStyle(fontSize: 12),
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const RestoreScreen()),
            ),
          ),
        ],
      ),
    );
  }
}

class _AboutCard extends StatelessWidget {
  const _AboutCard();

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Column(
        children: [
          const ListTile(
            leading: FloraLogo(size: 40),
            title: Text('FLORA'),
            subtitle: Text(
              'Farm Land Operations and Resource Automation',
              style: TextStyle(fontSize: 12),
            ),
          ),
          const Divider(height: 1),
          const ListTile(
            leading: Icon(Icons.memory),
            title: Text('Version'),
            subtitle: Text('0.1.0', style: TextStyle(fontSize: 12)),
          ),
          const Divider(height: 1),
          const Padding(
            padding: EdgeInsets.all(Gap.lg),
            child: Text(
              'Your devices decide when to water. The cloud only carries readings and '
              'passes your requests along; it never decides for the farm. No email, name, '
              'or phone number is collected.',
              style: TextStyle(fontSize: 12, color: FloraColors.muted, height: 1.4),
            ),
          ),
        ],
      ),
    );
  }
}
