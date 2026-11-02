import 'package:flutter/material.dart';

import 'core/theme.dart';
import 'screens/shell.dart';

/// The root widget.
///
/// There is no router dependency: the app has one shell with tabs and a handful
/// of pushed screens, so a named-route table would be more machinery than the
/// navigation needs. Where a route does carry an argument, it takes a typed
/// object rather than a string, so a malformed argument cannot reach a screen.
class FloraApp extends StatelessWidget {
  const FloraApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'FLORA',
      theme: floraTheme(),
      debugShowCheckedModeBanner: false,
      // The shell is the only top-level screen; everything else is pushed.
      home: const ShellScreen(),
      builder: (context, child) {
        // Cap text scaling so a large system font cannot break the metric rows,
        // which are two-column and would otherwise overflow.
        final media = MediaQuery.of(context);
        final scale = media.textScaler.clamp(
          minScaleFactor: 0.8,
          maxScaleFactor: 1.3,
        );
        return MediaQuery(
          data: media.copyWith(textScaler: scale),
          child: child ?? const SizedBox.shrink(),
        );
      },
    );
  }
}
