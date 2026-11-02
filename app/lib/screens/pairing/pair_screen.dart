import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../core/theme.dart';
import '../../data/api/api_client.dart';
import '../../data/auth/keypair.dart';
import '../../data/pairing/qr_payload.dart';
import '../../providers/providers.dart';
import '../../widgets/common.dart';
import '../recovery/show_phrase_screen.dart';

/// Scan the QR that came with a gateway, then claim it.
///
/// The claim is the only place an account comes into existence, so this screen
/// is also where the recovery phrase is first offered. It is offered, not
/// demanded: forcing someone to write twelve words before they can see their
/// own plot would be hostile.
class PairScreen extends ConsumerStatefulWidget {
  const PairScreen({super.key});

  @override
  ConsumerState<PairScreen> createState() => _PairScreenState();
}

class _PairScreenState extends ConsumerState<PairScreen> {
  final _controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.noDuplicates,
    formats: const [BarcodeFormat.qrCode],
  );

  bool _busy = false;
  bool _torchOn = false;
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  /// Handle a scan, guarding against a second decode while one is processing.
  Future<void> _onDetect(BarcodeCapture capture) async {
    if (_busy || _error != null) return;
    final raw = capture.barcodes
        .map((barcode) => barcode.rawValue)
        .whereType<String>()
        .firstOrNull;
    if (raw == null || raw.isEmpty) return;

    final QrPayload payload;
    try {
      payload = QrPayload.parse(raw);
    } on PairingError catch (error) {
      // Stop scanning so the message is readable rather than flashing past.
      setState(() {
        _busy = true;
        _error = error.message;
      });
      await _controller.stop();
      return;
    }

    setState(() => _busy = true);
    await _controller.stop();
    await _claim(payload);
  }

  Future<void> _claim(QrPayload payload) async {
    final cloud = ref.read(cloudProvider);
    try {
      final keypair = await _keypair();
      final result = await cloud.claim(payload: payload, keypair: keypair);
      await ref.read(accountProvider.notifier).onClaimed();
      if (!mounted) return;

      if (result.accountCreated) {
        // The account was created by this scan, so this is the only moment the
        // phrase can be offered before the user has anything to lose.
        await Navigator.of(context).push(
          MaterialPageRoute<void>(
            builder: (_) => const ShowPhraseScreen(firstTime: true),
          ),
        );
      }
      if (!mounted) return;
      Navigator.of(context).pop(true);
    } on ApiFailure catch (failure) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = failure.message;
      });
      await _controller.start();
    } on PairingError catch (error) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = error.message;
      });
    } on KeystoreUnavailable catch (error) {
      // Already phrased for a person. Prefixing it would bury the one detail
      // that tells them what to do.
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
        _error = 'Could not pair this device. $error';
      });
      await _controller.start();
    }
  }

  /// The key on this device, creating one on first use.
  ///
  /// Created here rather than at startup so the app does not mint an identity
  /// for someone who never pairs anything.
  Future<AppKeypair> _keypair() async {
    final existing = await ref.read(keypairProvider.future);
    if (existing != null) return existing;
    final created = await KeypairStore().loadOrCreate();
    ref.invalidate(keypairProvider);
    return created;
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
      appBar: AppBar(
        // First screen a new user sees, so it carries the brand mark.
        title: const Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            FloraLogo(size: 28),
            SizedBox(width: Gap.sm),
            Text('Scan the code'),
          ],
        ),
        actions: [
          IconButton(
            tooltip: _torchOn ? 'Turn the light off' : 'Turn the light on',
            onPressed: () async {
              await _controller.toggleTorch();
              setState(() => _torchOn = !_torchOn);
            },
            icon: Icon(_torchOn ? Icons.flashlight_off : Icons.flashlight_on),
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: Stack(
              fit: StackFit.expand,
              children: [
                MobileScanner(
                  controller: _controller,
                  onDetect: _onDetect,
                  errorBuilder: (context, error) => _ScannerUnavailable(
                    message: _describeScannerError(error),
                  ),
                ),
                if (_busy && _error == null) const _ScanProgress(),
                if (_error != null)
                  _ScanError(message: _error!, onRetry: _reset),
              ],
            ),
          ),
          const _ScanHint(),
        ],
      ),
    );
  }

  /// Turn a scanner error into something a person can act on.
  ///
  /// The old app let any exception during scanning reach the framework, which
  /// produced an error screen with no explanation. Camera permission is the
  /// common cause and the only one the user can fix.
  String _describeScannerError(MobileScannerException error) {
    return switch (error.errorCode) {
      MobileScannerErrorCode.permissionDenied =>
        'FLORA needs camera access to read the pairing code. Allow the camera in your phone settings, then try again.',
      MobileScannerErrorCode.unsupported =>
        'This device cannot scan codes. Enter the details from the label instead.',
      _ => 'The camera could not start. Close other apps using it and try again.',
    };
  }
}

/// Overlay shown while a claim is in flight.
class _ScanProgress extends StatelessWidget {
  const _ScanProgress();

  @override
  Widget build(BuildContext context) {
    return ColoredBox(
      color: Colors.black54,
      child: const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(color: Colors.white),
            SizedBox(height: Gap.lg),
            Text(
              'Pairing…',
              style: TextStyle(color: Colors.white, fontWeight: FontWeight.w600),
            ),
          ],
        ),
      ),
    );
  }
}

/// Overlay shown when the code is wrong or the claim was refused.
class _ScanError extends StatelessWidget {
  const _ScanError({required this.message, required this.onRetry});

  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    return ColoredBox(
      color: Colors.black87,
      child: Padding(
        padding: const EdgeInsets.all(Gap.xl),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, color: Colors.white, size: 48),
            const SizedBox(height: Gap.lg),
            Text(
              message,
              textAlign: TextAlign.center,
              style: const TextStyle(color: Colors.white, fontSize: 15),
            ),
            const SizedBox(height: Gap.xl),
            SizedBox(
              width: 220,
              child: FilledButton(
                onPressed: onRetry,
                child: const Text('Scan again'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Shown when the camera itself cannot start.
class _ScannerUnavailable extends StatelessWidget {
  const _ScannerUnavailable({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return ColoredBox(
      color: FloraColors.paper,
      child: Padding(
        padding: const EdgeInsets.all(Gap.xl),
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.no_photography_outlined, size: 52, color: FloraColors.clay),
              const SizedBox(height: Gap.lg),
              Text(
                message,
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 15, color: FloraColors.ink),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Instructions under the camera, so the user knows what to point at.
class _ScanHint extends StatelessWidget {
  const _ScanHint();

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      color: FloraColors.surface,
      padding: const EdgeInsets.all(Gap.lg),
      child: const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Point the camera at the square code',
            style: TextStyle(fontSize: 15, fontWeight: FontWeight.w700, color: FloraColors.ink),
          ),
          SizedBox(height: Gap.xs),
          Text(
            'It is printed on the card that came with your FLORA box. Codes expire after 24 hours; '
            'if this one has, ask for a new one.',
            style: TextStyle(fontSize: 13, color: FloraColors.muted),
          ),
        ],
      ),
    );
  }
}
