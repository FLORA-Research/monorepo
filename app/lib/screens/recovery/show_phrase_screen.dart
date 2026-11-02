import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/theme.dart';
import '../../data/auth/mnemonic.dart';
import '../../providers/providers.dart';
import '../../widgets/common.dart';

/// Show the twelve-word recovery phrase.
///
/// This is the account. There is no email and no password to fall back on, so
/// losing both the phone and the phrase loses everything. The screen says that
/// plainly rather than softening it, because a farmer who does not understand
/// the stakes will not write the words down.
class ShowPhraseScreen extends ConsumerStatefulWidget {
  const ShowPhraseScreen({super.key, this.firstTime = false});

  /// When true, this appeared straight after the first successful pairing, so
  /// the framing is "save this now" rather than "here it is again".
  final bool firstTime;

  @override
  ConsumerState<ShowPhraseScreen> createState() => _ShowPhraseScreenState();
}

class _ShowPhraseScreenState extends ConsumerState<ShowPhraseScreen> {
  bool _acknowledged = false;

  @override
  Widget build(BuildContext context) {
    final phrase = ref.watch(recoveryPhraseProvider);

    return Scaffold(
      appBar: AppBar(
        title: Text(widget.firstTime ? 'Save your recovery phrase' : 'Recovery phrase'),
        automaticallyImplyLeading: !widget.firstTime,
      ),
      body: SafeArea(
        child: phrase.when(
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (error, _) => ErrorState(
            message: 'Could not read the recovery phrase. $error',
          ),
          data: (value) {
            if (value == null) {
              return const EmptyState(
                icon: Icons.key_off_outlined,
                title: 'No phrase yet',
                body: 'Pair a device first. The phrase is created with your account.',
              );
            }
            return _PhraseBody(
              phrase: value,
              acknowledged: _acknowledged,
              onAcknowledged: (value) => setState(() => _acknowledged = value),
              onDone: () => Navigator.of(context).pop(),
              firstTime: widget.firstTime,
            );
          },
        ),
      ),
    );
  }
}

class _PhraseBody extends StatelessWidget {
  const _PhraseBody({
    required this.phrase,
    required this.acknowledged,
    required this.onAcknowledged,
    required this.onDone,
    required this.firstTime,
  });

  final String phrase;
  final bool acknowledged;
  final ValueChanged<bool> onAcknowledged;
  final VoidCallback onDone;
  final bool firstTime;

  @override
  Widget build(BuildContext context) {
    final words = RecoveryPhrase.words(phrase);

    return ListView(
      padding: const EdgeInsets.all(Gap.lg),
      children: [
        Container(
          padding: const EdgeInsets.all(Gap.lg),
          decoration: BoxDecoration(
            color: FloraColors.clay.withValues(alpha: 0.10),
            borderRadius: BorderRadius.circular(Corners.card),
            border: Border.all(color: FloraColors.clay.withValues(alpha: 0.4)),
          ),
          child: const Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.warning_amber_rounded, color: FloraColors.clay),
              SizedBox(width: Gap.md),
              Expanded(
                child: Text(
                  'Write these twelve words on paper and keep them somewhere safe. '
                  'Anyone who has them can control your farm. If you lose your phone '
                  'and these words, your account cannot be recovered — there is no '
                  'email or password to reset.',
                  style: TextStyle(fontSize: 14, color: FloraColors.ink, height: 1.4),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: Gap.xl),
        _WordGrid(words: words),
        const SizedBox(height: Gap.lg),
        Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: () async {
                  await Clipboard.setData(ClipboardData(text: phrase));
                  if (!context.mounted) return;
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Copied. Remember that a clipboard can be read by other apps.'),
                    ),
                  );
                },
                icon: const Icon(Icons.copy_all_outlined, size: 18),
                label: const Text('Copy'),
              ),
            ),
          ],
        ),
        const SizedBox(height: Gap.xl),
        CheckboxListTile(
          value: acknowledged,
          onChanged: (value) => onAcknowledged(value ?? false),
          controlAffinity: ListTileControlAffinity.leading,
          contentPadding: EdgeInsets.zero,
          title: const Text(
            'I have written these words down',
            style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
          ),
          subtitle: const Text(
            'You can view them again in Settings while this phone still has your account.',
            style: TextStyle(fontSize: 12, color: FloraColors.muted),
          ),
        ),
        const SizedBox(height: Gap.lg),
        FilledButton(
          // Enabled only once acknowledged, so the screen cannot be dismissed by
          // a stray tap before the words are recorded.
          onPressed: acknowledged ? onDone : null,
          child: Text(firstTime ? 'Continue' : 'Done'),
        ),
      ],
    );
  }
}

/// The twelve words, numbered so order is unambiguous.
class _WordGrid extends StatelessWidget {
  const _WordGrid({required this.words});

  final List<String> words;

  @override
  Widget build(BuildContext context) {
    // Two columns, as a grid rather than a wrap, so the numbering lines up.
    return Wrap(
      spacing: Gap.sm,
      runSpacing: Gap.sm,
      children: [
        for (var index = 0; index < words.length; index++)
          SizedBox(
            width: (MediaQuery.sizeOf(context).width - Gap.lg * 2 - Gap.sm) / 2,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: Gap.md, vertical: Gap.md),
              decoration: BoxDecoration(
                color: FloraColors.surface,
                borderRadius: BorderRadius.circular(Corners.field),
                border: Border.all(color: FloraColors.line),
              ),
              child: Row(
                children: [
                  SizedBox(
                    width: 22,
                    child: Text(
                      '${index + 1}',
                      style: const TextStyle(fontSize: 12, color: FloraColors.muted),
                    ),
                  ),
                  Expanded(
                    child: Text(
                      words[index],
                      style: const TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                        color: FloraColors.ink,
                        letterSpacing: 0.2,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
      ],
    );
  }
}
