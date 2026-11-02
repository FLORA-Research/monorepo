import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // Nothing is awaited here. The old app awaited the store before `runApp`,
  // which meant any storage failure produced a blank or error screen and the
  // user never saw the app at all. Restoring happens inside a provider, so the
  // first frame always renders and a failure is shown in place.
  runApp(const ProviderScope(child: FloraApp()));
}
