import 'package:flutter/material.dart';

import '../core/format.dart';
import '../core/theme.dart';

/// A labelled reading, with the unavailable case shown as a dash rather than a
/// number that would read as a real value.
class MetricTile extends StatelessWidget {
  const MetricTile({
    super.key,
    required this.label,
    required this.value,
    this.icon,
    this.tint,
    this.hint,
  });

  final String label;
  final String value;
  final IconData? icon;
  final Color? tint;

  /// Shown under the value when the reading needs explaining, such as
  /// "not calibrated".
  final String? hint;

  @override
  Widget build(BuildContext context) {
    final unavailable = value == '--';
    final colour = unavailable ? FloraColors.muted : (tint ?? FloraColors.ink);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: Gap.sm),
      child: Row(
        children: [
          if (icon != null) ...[
            Icon(icon, size: 18, color: FloraColors.muted),
            const SizedBox(width: Gap.sm),
          ],
          Expanded(
            child: Text(
              label,
              style: const TextStyle(fontSize: 14, color: FloraColors.muted),
            ),
          ),
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text(
                value,
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                  color: colour,
                ),
              ),
              if (hint != null)
                Text(
                  hint!,
                  style: const TextStyle(fontSize: 11, color: FloraColors.muted),
                ),
            ],
          ),
        ],
      ),
    );
  }
}

/// A moisture gauge.
///
/// The colour reflects the device's own dry and wet points rather than an
/// opinion of the app's, and an unavailable reading shows as an empty track
/// instead of an empty-looking tank.
class MoistureGauge extends StatelessWidget {
  const MoistureGauge({
    super.key,
    required this.value,
    this.height = 8,
  });

  /// Percent, or null when the probe is unavailable.
  final double? value;
  final double height;

  @override
  Widget build(BuildContext context) {
    final filled = value == null ? 0.0 : (value! / MoistureScale.max).clamp(0.0, 1.0);
    final colour = value == null
        ? FloraColors.line
        : value! <= MoistureScale.dry
            ? FloraColors.clay
            : value! >= MoistureScale.wet
                ? FloraColors.water
                : FloraColors.leaf;

    return ClipRRect(
      borderRadius: BorderRadius.circular(height),
      child: SizedBox(
        height: height,
        child: Stack(
          children: [
            Container(color: FloraColors.line),
            FractionallySizedBox(
              widthFactor: filled,
              child: Container(color: colour),
            ),
          ],
        ),
      ),
    );
  }
}

/// A valve state indicator.
class ValveChip extends StatelessWidget {
  const ValveChip({super.key, required this.open, this.compact = false});

  /// Null means the state was not reported.
  final bool? open;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final (colour, icon, text) = switch (open) {
      true => (FloraColors.water, Icons.water_drop, 'Watering'),
      false => (FloraColors.muted, Icons.water_drop_outlined, 'Closed'),
      null => (FloraColors.line, Icons.help_outline, 'Unknown'),
    };

    return Container(
      padding: EdgeInsets.symmetric(
        horizontal: compact ? Gap.sm : Gap.md,
        vertical: compact ? 2 : Gap.xs,
      ),
      decoration: BoxDecoration(
        color: colour.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(Corners.chip),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: compact ? 12 : 14, color: colour),
          const SizedBox(width: Gap.xs),
          Text(
            text,
            style: TextStyle(
              fontSize: compact ? 11 : 12,
              fontWeight: FontWeight.w600,
              color: colour,
            ),
          ),
        ],
      ),
    );
  }
}

/// An empty state that says what to do next rather than only what is missing.
class EmptyState extends StatelessWidget {
  const EmptyState({
    super.key,
    required this.icon,
    required this.title,
    required this.body,
    this.action,
  });

  final IconData icon;
  final String title;
  final String body;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(Gap.xxl),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 56, color: FloraColors.line),
            const SizedBox(height: Gap.lg),
            Text(
              title,
              textAlign: TextAlign.center,
              style: const TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w700,
                color: FloraColors.ink,
              ),
            ),
            const SizedBox(height: Gap.sm),
            Text(
              body,
              textAlign: TextAlign.center,
              style: const TextStyle(fontSize: 14, color: FloraColors.muted),
            ),
            if (action != null) ...[
              const SizedBox(height: Gap.xl),
              action!,
            ],
          ],
        ),
      ),
    );
  }
}

/// A failure with a retry, used wherever a fetch can fail.
class ErrorState extends StatelessWidget {
  const ErrorState({
    super.key,
    required this.message,
    this.onRetry,
  });

  final String message;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(Gap.xxl),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.cloud_off_outlined, size: 48, color: FloraColors.clay),
            const SizedBox(height: Gap.lg),
            Text(
              message,
              textAlign: TextAlign.center,
              style: const TextStyle(fontSize: 14, color: FloraColors.ink),
            ),
            if (onRetry != null) ...[
              const SizedBox(height: Gap.xl),
              SizedBox(
                width: 200,
                child: OutlinedButton(
                  onPressed: onRetry,
                  child: const Text('Try again'),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// A small status pill, used for the live indicator and gateway state.
class StatusPill extends StatelessWidget {
  const StatusPill({
    super.key,
    required this.text,
    required this.colour,
    this.icon,
  });

  final String text;
  final Color colour;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: Gap.sm, vertical: 3),
      decoration: BoxDecoration(
        color: colour.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(Corners.chip),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: 12, color: colour),
            const SizedBox(width: Gap.xs),
          ],
          Text(
            text,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w700,
              color: colour,
            ),
          ),
        ],
      ),
    );
  }
}

/// The FLORA mascot logo, loaded from the bundled brand asset.
class FloraLogo extends StatelessWidget {
  const FloraLogo({super.key, this.size = 40});

  /// Rendered edge length in logical pixels.
  final double size;

  @override
  Widget build(BuildContext context) {
    return ClipRRect(
      borderRadius: BorderRadius.circular(size * 0.22),
      child: Image.asset(
        'assets/brand/logo.png',
        width: size,
        height: size,
        fit: BoxFit.cover,
        // Brand art, not content, so it does not participate in semantics.
        excludeFromSemantics: true,
      ),
    );
  }
}

/// A section heading with consistent spacing.
class SectionHeading extends StatelessWidget {
  const SectionHeading(this.title, {super.key, this.trailing});

  final String title;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: Gap.sm),
      child: Row(
        children: [
          Expanded(
            child: Text(
              title,
              style: const TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w700,
                letterSpacing: 0.4,
                color: FloraColors.muted,
              ),
            ),
          ),
          if (trailing != null) trailing!,
        ],
      ),
    );
  }
}

/// A shared page scaffold, so every top-level screen has the same padding.
class PageBody extends StatelessWidget {
  const PageBody({
    super.key,
    required this.title,
    required this.child,
    this.actions,
    this.onRefresh,
  });

  final String title;
  final Widget child;
  final List<Widget>? actions;
  final Future<void> Function()? onRefresh;

  @override
  Widget build(BuildContext context) {
    final content = ListView(
      padding: const EdgeInsets.fromLTRB(Gap.lg, Gap.lg, Gap.lg, Gap.xxl),
      children: [child],
    );

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(Gap.lg, Gap.lg, Gap.lg, Gap.sm),
          child: Row(
            children: [
              const FloraLogo(size: 34),
              const SizedBox(width: Gap.md),
              Expanded(
                child: Text(
                  title,
                  style: const TextStyle(
                    fontSize: 28,
                    fontWeight: FontWeight.w800,
                    color: FloraColors.ink,
                  ),
                ),
              ),
              ...?actions,
            ],
          ),
        ),
        Expanded(
          child: onRefresh == null
              ? content
              : RefreshIndicator(
                  onRefresh: onRefresh!,
                  color: FloraColors.soil,
                  child: content,
                ),
        ),
      ],
    );
  }
}
