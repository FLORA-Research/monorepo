import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../data/api/api_client.dart';
import '../../core/theme.dart';
import '../../data/models/models.dart';
import '../../providers/providers.dart';

/// Rename a gateway.
///
/// The rename is applied locally only after the server accepts it, so a failure
/// leaves the old name rather than a name that silently reverts on next launch.
Future<void> renameGateway(BuildContext context, WidgetRef ref, Gateway gateway) async {
  final name = await _promptLabel(
    context,
    title: 'Name this plot',
    initial: gateway.label ?? '',
    hint: 'For example: plot-north',
  );
  if (name == null) return;

  try {
    final updated = await ref.read(cloudProvider).renameGateway(gateway.id, name);
    ref.read(accountProvider.notifier).applyLabel(gateway.id, updated.label);
    if (context.mounted) {
      _snack(context, name.isEmpty ? 'Name cleared.' : 'Renamed to "$name".');
    }
  } on ApiFailure catch (failure) {
    if (context.mounted) _snack(context, failure.message);
  }
}

/// Rename a node.
Future<void> renameNode(
  BuildContext context,
  WidgetRef ref,
  Gateway gateway,
  Node node,
) async {
  final name = await _promptLabel(
    context,
    title: 'Name this node',
    initial: node.label ?? '',
    hint: 'For example: north bed',
  );
  if (name == null) return;

  try {
    await ref.read(cloudProvider).renameNode(gateway.id, node.uuid, name);
    // Refetch so the list reflects what the server stored.
    await ref.read(telemetryProvider(gateway.id).notifier).refresh();
    if (context.mounted) {
      _snack(context, name.isEmpty ? 'Name cleared.' : 'Renamed to "$name".');
    }
  } on ApiFailure catch (failure) {
    if (context.mounted) _snack(context, failure.message);
  }
}

/// A single-field prompt that cleans up its controller correctly.
///
/// The old app disposed the controller in `whenComplete`, which can run while
/// the dialog is still animating out and produces a "used after dispose"
/// exception. Here the controller is owned by a stateful widget, so its
/// lifetime matches the dialog's.
Future<String?> _promptLabel(
  BuildContext context, {
  required String title,
  required String initial,
  required String hint,
}) {
  return showDialog<String>(
    context: context,
    builder: (dialogContext) => _LabelDialog(
      title: title,
      initial: initial,
      hint: hint,
    ),
  );
}

class _LabelDialog extends StatefulWidget {
  const _LabelDialog({
    required this.title,
    required this.initial,
    required this.hint,
  });

  final String title;
  final String initial;
  final String hint;

  @override
  State<_LabelDialog> createState() => _LabelDialogState();
}

class _LabelDialogState extends State<_LabelDialog> {
  late final TextEditingController _controller;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: widget.initial);
  }

  @override
  void dispose() {
    // Disposed only when the dialog itself is removed from the tree, which is
    // after the exit animation, so nothing can touch it too early.
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.title),
      content: TextField(
        controller: _controller,
        autofocus: true,
        maxLength: kMaxLabel,
        textCapitalization: TextCapitalization.sentences,
        decoration: InputDecoration(
          hintText: widget.hint,
          counterText: '',
        ),
        onSubmitted: (value) => Navigator.of(context).pop(value.trim()),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(_controller.text.trim()),
          child: const Text('Save'),
        ),
      ],
    );
  }
}

void _snack(BuildContext context, String message) {
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
}

/// Mirrors the server's limit so the field caps input before a round trip.
const int kMaxLabel = 64;

/// A confirmation dialog for a destructive action.
Future<bool> confirmDestructive(
  BuildContext context, {
  required String title,
  required String body,
  required String confirmLabel,
}) async {
  final result = await showDialog<bool>(
    context: context,
    builder: (dialogContext) => AlertDialog(
      title: Text(title),
      content: Text(body),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(dialogContext).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          style: FilledButton.styleFrom(
            backgroundColor: FloraColors.alarm,
            minimumSize: const Size(88, 44),
          ),
          onPressed: () => Navigator.of(dialogContext).pop(true),
          child: Text(confirmLabel),
        ),
      ],
    ),
  );
  return result ?? false;
}
