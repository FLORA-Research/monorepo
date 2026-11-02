import 'package:flutter/material.dart';

/// The app's palette and type.
///
/// Colours are named for what they mean on a farm rather than for their hue, so
/// a change to the palette does not read as a change to the meaning.
///
/// The hues come from the logo (`assets/icon/icon.png`): sky `#84C1FF`, leaf
/// `#88CB67`, and soil `#88552E`. Each semantic colour below keeps that hue and
/// adjusts only lightness, so text stays AA-contrast on paper while the palette
/// still reads as the brand. [`sprout`] and [`sky`] are the two icon colours
/// kept exactly, for fills where contrast is not the job.
abstract final class FloraColors {
  /// Earth from the logo, deepened: the header and emphasis surface.
  static const soil = Color(0xFF4A2D17);

  /// Leaf green from the logo, darkened for text and selected states.
  static const leaf = Color(0xFF528D34);

  /// The logo's leaf green exactly, for fills and progress tracks.
  static const sprout = Color(0xFF88CB67);

  /// The logo's sky exactly, for tinted backgrounds and moisture fills.
  static const sky = Color(0xFF84C1FF);

  /// Dry earth, used for warnings and the "dry" moisture state.
  static const clay = Color(0xFFAD6834);

  /// Water, used for moisture and the valve-open state.
  static const water = Color(0xFF3878BC);

  /// Paper, the default background: warm, tinted by the soil hue.
  static const paper = Color(0xFFF8F6F2);

  /// Card surface, slightly lifted from paper.
  static const surface = Color(0xFFFDFCFA);

  /// Primary text.
  static const ink = Color(0xFF181411);

  /// Secondary text.
  static const muted = Color(0xFF6E675E);

  /// Divider and outline.
  static const line = Color(0xFFE4DED2);

  /// A failure the user must act on.
  static const alarm = Color(0xFFB3341F);
}

/// Spacing scale, so padding is consistent rather than per-screen guesswork.
abstract final class Gap {
  static const double xs = 4;
  static const double sm = 8;
  static const double md = 12;
  static const double lg = 16;
  static const double xl = 24;
  static const double xxl = 32;
}

/// Corner radii.
abstract final class Corners {
  static const double card = 16;
  static const double chip = 999;
  static const double field = 12;
}

ThemeData floraTheme() {
  // Seeded from the logo's own green, then the semantic roles are pinned to
  // the palette. `onPrimary`/`onSecondary` are set explicitly rather than
  // inherited: a copied scheme keeps the seed's contrast pair, which is not
  // necessarily readable against the overridden colour.
  final scheme = ColorScheme.fromSeed(
    seedColor: FloraColors.sprout,
    brightness: Brightness.light,
  ).copyWith(
    primary: FloraColors.soil,
    onPrimary: FloraColors.paper,
    secondary: FloraColors.leaf,
    onSecondary: FloraColors.paper,
    tertiary: FloraColors.water,
    surface: FloraColors.surface,
    error: FloraColors.alarm,
  );

  final base = ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: FloraColors.paper,
  );

  return base.copyWith(
    appBarTheme: const AppBarTheme(
      backgroundColor: FloraColors.paper,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: false,
      titleTextStyle: TextStyle(
        color: FloraColors.ink,
        fontSize: 22,
        fontWeight: FontWeight.w700,
      ),
      iconTheme: IconThemeData(color: FloraColors.ink),
    ),
    cardTheme: CardThemeData(
      color: FloraColors.surface,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Corners.card),
        side: const BorderSide(color: FloraColors.line),
      ),
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: FloraColors.surface,
      surfaceTintColor: Colors.transparent,
      indicatorColor: FloraColors.leaf.withValues(alpha: 0.16),
      elevation: 0,
      height: 68,
      labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
      labelTextStyle: WidgetStateProperty.resolveWith(
        (states) => TextStyle(
          fontSize: 12,
          fontWeight: states.contains(WidgetState.selected) ? FontWeight.w700 : FontWeight.w500,
          color: states.contains(WidgetState.selected) ? FloraColors.soil : FloraColors.muted,
        ),
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: FloraColors.soil,
        foregroundColor: Colors.white,
        minimumSize: const Size.fromHeight(52),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Corners.field),
        ),
        textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: FloraColors.soil,
        minimumSize: const Size.fromHeight(52),
        side: const BorderSide(color: FloraColors.line),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Corners.field),
        ),
        textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: FloraColors.surface,
      contentPadding: const EdgeInsets.symmetric(horizontal: Gap.lg, vertical: Gap.md),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(Corners.field),
        borderSide: const BorderSide(color: FloraColors.line),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(Corners.field),
        borderSide: const BorderSide(color: FloraColors.line),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(Corners.field),
        borderSide: const BorderSide(color: FloraColors.leaf, width: 2),
      ),
      labelStyle: const TextStyle(color: FloraColors.muted),
    ),
    dividerTheme: const DividerThemeData(
      color: FloraColors.line,
      thickness: 1,
      space: 1,
    ),
    listTileTheme: const ListTileThemeData(
      iconColor: FloraColors.soil,
      textColor: FloraColors.ink,
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      backgroundColor: FloraColors.ink,
      contentTextStyle: const TextStyle(color: Colors.white),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Corners.field),
      ),
    ),
    bottomSheetTheme: const BottomSheetThemeData(
      backgroundColor: FloraColors.surface,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(Corners.card)),
      ),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: FloraColors.surface,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Corners.card),
      ),
    ),
    progressIndicatorTheme: const ProgressIndicatorThemeData(
      color: FloraColors.leaf,
    ),
  );
}
