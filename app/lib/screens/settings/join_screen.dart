import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../core/protocol.dart';
import '../../core/theme.dart';
import '../../data/api/api_client.dart';
import '../../data/pairing/qr_payload.dart';
import '../../data/auth/keypair.dart';
import '../../providers/providers.dart';

/// Join an existing account by scanning an invite.
///
/// The counterpart to the invite screen. A phone that already belongs to one
/// account cannot join another: the app refuses rather than replacing the local
/// identity, because silently switching accounts would lose the first farm.
class JoinScreen extends ConsumerStatefulWidget {
  const JoinScreen({super.key});

  @override
  ConsumerState<JoinScreen> createState() => _JoinScreenState();
}

class _JoinScreenState extends ConsumerState<JoinScreen> {
  final _controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.noDuplicates,
    formats: const [BarcodeFormat.qrCode],
  );

  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  /// Parse `flora://invite?v=1&a=<account>&t=<token>`.
  ({String token, String accountId})? _parse(String raw) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null || uri.scheme != 'flora' || uri.host != 'invite') return null;
    if (uri.queryParameters['v'] != '1') return null;
    final token = uri.queryParameters['t']?.trim().toLowerCase();
    final account = uri.queryParameters['a']?.trim();
    if (token == null || token.length != Protocol.tokenLength * 2) return null;
    if (account == null || account.isEmpty) return null;
    return (token: token, accountId: account);
  }

  Future<void> _onDetect(BarcodeCapture capture) async {
    if (_busy) return;
    final raw = capture.barcodes
        .map((barcode) => barcode.rawValue)
        .whereType<String>()
        .firstOrNull;
    if (raw == null) return;

    final parsed = _parse(raw);
    if (parsed == null) {
      setState(() {
        _busy = true;
        _error = 'That is not a FLORA invite. Ask for a new code from the other phone.';
      });
      await _controller.stop();
      return;
    }

    setState(() => _busy = true);
    await _controller.stop();
    await _join(parsed.token);
  }

  Future<void> _join(String token) async {
    try {
      // Reuse the key on this device if there is one, so joining does not
      // discard an identity the user may already rely on.
      final keypair = await ref.read(keypairProvider.future) ??
          await KeypairStore().loadOrCreate();
      await ref.read(cloudProvider).redeemInvite(
            inviteToken: token,
            keypair: keypair,
          );
      ref.invalidate(keypairProvider);
      await ref.read(accountProvider.notifier).refresh();
      if (!mounted) return;
      Navigator.of(context).pop(true);
    } on ApiFailure catch (failure) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = failure.message;
      });
      await _controller.start();
    } on KeystoreUnavailable catch (error) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = error.message;
      });
      await _controller.start();
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = 'Could not join. $error';
      });
      await _controller.start();
    }
  }

  void _reset() {
    setState(() {
      _busy = false;
      _error = null;
    });
    _controller.start();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Join with a code')),
      body: Stack(
        fit: StackFit.expand,
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
            errorBuilder: (context, error) => Center(
              child: Padding(
                padding: const EdgeInsets.all(Gap.xl),
                child: Text(
                  error.errorCode == MobileScannerErrorCode.permissionDenied
                      ? 'FLORA needs camera access to read the invite. Allow the camera in '
                          'your phone settings, then try again.'
                      : 'The camera could not start. Close other apps using it and try again.',
                  textAlign: TextAlign.center,
                  style: const TextStyle(fontSize: 15, color: FloraColors.ink),
                ),
              ),
            ),
          ),
          if (_busy && _error == null)
            const ColoredBox(
              color: Colors.black54,
              child: Center(child: CircularProgressIndicator(color: Colors.white)),
            ),
          if (_error != null)
            ColoredBox(
              color: Colors.black87,
              child: Padding(
                padding: const EdgeInsets.all(Gap.xl),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const Icon(Icons.error_outline, color: Colors.white, size: 48),
                    const SizedBox(height: Gap.lg),
                    Text(
                      _error!,
                      textAlign: TextAlign.center,
                      style: const TextStyle(color: Colors.white, fontSize: 15),
                    ),
                    const SizedBox(height: Gap.xl),
                    SizedBox(
                      width: 220,
                      child: FilledButton(
                        onPressed: _reset,
                        child: const Text('Scan again'),
                      ),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}
