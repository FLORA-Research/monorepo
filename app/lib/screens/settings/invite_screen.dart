import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../core/theme.dart';
import '../../data/api/api_client.dart';
import '../../data/api/cloud_repository.dart';
import '../../providers/providers.dart';
import '../../widgets/common.dart';

/// Invite a second phone to this account.
///
/// No email is involved: the inviter shows a code, the other phone scans it.
/// The invite is short-lived and single-use, so a code photographed off a
/// screen stops working within minutes.
class InviteScreen extends ConsumerStatefulWidget {
  const InviteScreen({super.key});

  @override
  ConsumerState<InviteScreen> createState() => _InviteScreenState();
}

class _InviteScreenState extends ConsumerState<InviteScreen> {
  InviteOffer? _offer;
  String? _error;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _mint();
  }

  Future<void> _mint() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final offer = await ref.read(cloudProvider).createInvite();
      if (!mounted) return;
      setState(() {
        _offer = offer;
        _loading = false;
      });
    } on ApiFailure catch (failure) {
      if (!mounted) return;
      setState(() {
        _error = failure.message;
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Invite a phone'),
        actions: [
          IconButton(
            tooltip: 'New code',
            onPressed: _loading ? null : _mint,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: SafeArea(
        child: _loading
            ? const Center(child: CircularProgressIndicator())
            : _error != null
                ? Center(
                    child: ErrorState(message: _error!, onRetry: _mint),
                  )
                : _body(_offer!),
      ),
    );
  }

  Widget _body(InviteOffer offer) {
    return ListView(
      padding: const EdgeInsets.all(Gap.lg),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(Gap.lg),
            child: Column(
              children: [
                const Text(
                  'Show this to the other phone',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: Gap.xs),
                const Text(
                  'They open FLORA, choose "Join with a code", and scan it.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 13, color: FloraColors.muted),
                ),
                const SizedBox(height: Gap.lg),
                // White behind the code, because a scanner needs contrast and a
                // themed background would lower it.
                Container(
                  padding: const EdgeInsets.all(Gap.lg),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    borderRadius: BorderRadius.circular(Corners.field),
                    border: Border.all(color: FloraColors.line),
                  ),
                  child: QrImageView(
                    data: offer.payload,
                    version: QrVersions.auto,
                    size: 220,
                    backgroundColor: Colors.white,
                    // An error-correcting level that tolerates a smudge or a
                    // reflection without making the code enormous.
                    errorCorrectionLevel: QrErrorCorrectLevel.M,
                  ),
                ),
                const SizedBox(height: Gap.lg),
                StatusPill(
                  text: 'Expires in ${offer.minutesRemaining} min',
                  colour: offer.minutesRemaining <= 3 ? FloraColors.clay : FloraColors.leaf,
                  icon: Icons.schedule,
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: Gap.lg),
        OutlinedButton.icon(
          onPressed: () async {
            // The token text as a fallback for a phone without a working camera.
            await Clipboard.setData(ClipboardData(text: offer.payload));
            if (!mounted) return;
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Invite copied.')),
            );
          },
          icon: const Icon(Icons.copy_all_outlined, size: 18),
          label: const Text('Copy the invite text'),
        ),
        const SizedBox(height: Gap.lg),
        const Text(
          'An invite lets another phone see and control this account. It works once and '
          'expires quickly. If someone else sees it, make a new one and let the old one lapse.',
          textAlign: TextAlign.center,
          style: TextStyle(fontSize: 12, color: FloraColors.muted, height: 1.4),
        ),
      ],
    );
  }
}
