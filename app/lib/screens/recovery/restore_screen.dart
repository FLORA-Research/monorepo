import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/theme.dart';
import '../../data/api/api_client.dart';
import '../../data/auth/keypair.dart';
import '../../data/auth/mnemonic.dart';
import '../../providers/providers.dart';

/// Restore an account on this phone from the twelve words.
///
/// Used on a new phone, or after the app was reinstalled. The phrase is used
/// **here**, on the device, and only the resulting signature is sent: a server
/// that never sees the phrase cannot lose it.
class RestoreScreen extends ConsumerStatefulWidget {
  const RestoreScreen({super.key});

  @override
  ConsumerState<RestoreScreen> createState() => _RestoreScreenState();
}

class _RestoreScreenState extends ConsumerState<RestoreScreen> {
  final _controller = TextEditingController();
  bool _busy = false;
  String? _error;
  bool _valid = false;

  @override
  void initState() {
    super.initState();
    _controller.addListener(_onChanged);
  }

  @override
  void dispose() {
    _controller.removeListener(_onChanged);
    _controller.dispose();
    super.dispose();
  }

  /// Enable the button only for a phrase that would actually derive a key.
  void _onChanged() {
    final valid = RecoveryPhrase.isValid(_controller.text);
    if (valid != _valid) setState(() => _valid = valid);
  }

  Future<void> _restore() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });

    try {
      final seed = await RecoveryPhrase.toSeed(_controller.text);
      // Replace the stored keypair, because restoring must yield the account
      // that owns the phrase rather than merging with whatever was here.
      final keypair = await KeypairStore().replaceWithSeed(seed);
      ref.invalidate(keypairProvider);

      final signedIn = await ref.read(cloudProvider).signIn(keypair);
      if (!signedIn) {
        // A phrase can be valid BIP39 and still belong to no account, so this is
        // its own case rather than a phrase error.
        throw const ApiFailure('That phrase is valid, but it did not match an account.');
      }
      await ref.read(accountProvider.notifier).refresh();
      if (!mounted) return;
      Navigator.of(context).pop(true);
    } on InvalidPhrase catch (error) {
      if (mounted) setState(() => _error = error.toString());
    } on ApiFailure catch (failure) {
      if (mounted) setState(() => _error = failure.message);
    } catch (error) {
      if (mounted) setState(() => _error = 'Could not restore. $error');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final wordCount = RecoveryPhrase.words(_controller.text).length;

    return Scaffold(
      appBar: AppBar(title: const Text('Restore account')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(Gap.lg),
          children: [
            const Text(
              'Type the twelve words from your recovery phrase, in order.',
              style: TextStyle(fontSize: 15, color: FloraColors.ink),
            ),
            const SizedBox(height: Gap.sm),
            const Text(
              'This phone becomes the same account as before, and every plot reappears.',
              style: TextStyle(fontSize: 13, color: FloraColors.muted),
            ),
            const SizedBox(height: Gap.xl),
            TextField(
              controller: _controller,
              enabled: !_busy,
              maxLines: 4,
              minLines: 3,
              autocorrect: false,
              enableSuggestions: false,
              textCapitalization: TextCapitalization.none,
              decoration: InputDecoration(
                labelText: 'Recovery phrase',
                hintText: 'one two three four …',
                helperText: '$wordCount of ${RecoveryPhrase.wordCount} words',
                border: const OutlineInputBorder(),
              ),
            ),
            if (_error != null) ...[
              const SizedBox(height: Gap.lg),
              Container(
                padding: const EdgeInsets.all(Gap.md),
                decoration: BoxDecoration(
                  color: FloraColors.alarm.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(Corners.field),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.error_outline, color: FloraColors.alarm, size: 20),
                    const SizedBox(width: Gap.sm),
                    Expanded(
                      child: Text(
                        _error!,
                        style: const TextStyle(fontSize: 13, color: FloraColors.alarm),
                      ),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: Gap.xl),
            FilledButton(
              onPressed: (_valid && !_busy) ? _restore : null,
              child: _busy
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                    )
                  : const Text('Restore'),
            ),
            const SizedBox(height: Gap.lg),
            const Text(
              'The words stay on this phone. They are never sent to the server.',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 12, color: FloraColors.muted),
            ),
          ],
        ),
      ),
    );
  }
}
