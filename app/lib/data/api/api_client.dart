import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dio/dio.dart';

/// A failure the UI can show a person.
///
/// Carries a message that is safe to display and a flag for whether retrying
/// could help, so the UI does not offer "try again" for a rejected credential.
class ApiFailure implements Exception {
  const ApiFailure(this.message, {this.statusCode, this.retryable = false});

  /// What to tell the user. Already phrased for a person, not a developer.
  final String message;

  /// HTTP status, when the failure came from the server.
  final int? statusCode;

  /// Whether an identical retry might succeed. False for 4xx, which will not
  /// change on its own.
  final bool retryable;

  /// Whether the device is offline rather than the server refusing.
  bool get isOffline => statusCode == null && message.contains('connection');

  /// Maps a transport or HTTP failure to something displayable.
  factory ApiFailure.fromDio(DioException error) {
    switch (error.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
        return const ApiFailure(
          'The server took too long to answer. Check your connection and try again.',
          retryable: true,
        );
      case DioExceptionType.connectionError:
        return const ApiFailure(
          'Cannot reach the server. Check your connection.',
          retryable: true,
        );
      case DioExceptionType.cancel:
        return const ApiFailure('The request was cancelled.');
      case DioExceptionType.badCertificate:
        return const ApiFailure(
          'The server certificate could not be verified.',
        );
      case DioExceptionType.badResponse:
        return ApiFailure._fromResponse(error.response);
      case DioExceptionType.unknown:
        if (error.error is SocketException) {
          return const ApiFailure(
            'Cannot reach the server. Check your connection.',
            retryable: true,
          );
        }
        return const ApiFailure('Something went wrong. Try again.', retryable: true);
      case DioExceptionType.transformTimeout:
        return const ApiFailure(
          'The server took too long to answer. Try again.',
          retryable: true,
        );
    }
  }

  factory ApiFailure._fromResponse(Response<dynamic>? response) {
    final status = response?.statusCode;
    // The API returns {"error": "..."} for application errors. Axum's own
    // rejections (415, 422) return a plain string instead, so both are handled.
    String? serverMessage;
    final data = response?.data;
    if (data is Map && data['error'] is String) {
      serverMessage = data['error'] as String;
    } else if (data is String && data.isNotEmpty && data.length < 200) {
      serverMessage = data;
    }

    final message = switch (status) {
      400 => serverMessage ?? 'That request was not accepted.',
      401 => 'You are not signed in on this device any more.',
      403 => serverMessage ?? 'This device or plot is not yours to change.',
      404 => 'Not found. It may have been removed.',
      409 => serverMessage ?? 'That conflicts with something already recorded.',
      413 => 'That request was too large.',
      415 => 'The server did not understand the request format.',
      422 => serverMessage ?? 'Some of the details were not valid.',
      429 => 'Too many attempts. Wait a moment and try again.',
      final int code when code >= 500 =>
        'The server had a problem. Try again shortly.',
      _ => serverMessage ?? 'Something went wrong.',
    };

    return ApiFailure(
      message,
      statusCode: status,
      // 5xx and 429 can succeed later; other 4xx cannot.
      retryable: status == null || status >= 500 || status == 429,
    );
  }

  /// A failure for a case the client detected before sending.
  factory ApiFailure.local(String message) => ApiFailure(message);

  @override
  String toString() => message;
}

/// Thin wrapper over Dio that turns every failure into an [ApiFailure].
///
/// Every call goes through here so no screen has to know about Dio, and so
/// error handling is consistent rather than per-screen guesswork.
class ApiClient {
  ApiClient({required String baseUrl, Dio? dio})
      : _dio = dio ??
            Dio(
              BaseOptions(
                baseUrl: baseUrl,
                connectTimeout: const Duration(seconds: 15),
                receiveTimeout: const Duration(seconds: 20),
                // Non-2xx is handled explicitly, so Dio should not throw on it.
                validateStatus: (status) => status != null && status < 500,
                headers: {'Content-Type': 'application/json'},
              ),
            );

  final Dio _dio;

  String get baseUrl => _dio.options.baseUrl;

  /// Replace the bearer token used for account requests.
  void setAccessToken(String? token) {
    if (token == null) {
      _dio.options.headers.remove('Authorization');
    } else {
      _dio.options.headers['Authorization'] = 'Bearer $token';
    }
  }

  /// Replace the device credential used for a gateway's own requests.
  ///
  /// A separate scheme from the bearer token, matching the server. Used only
  /// by tooling, not by the phone.
  void setDeviceCredential(String? deviceId, String? tokenHex) {
    if (deviceId == null || tokenHex == null) {
      _dio.options.headers.remove('X-Device-Authorization');
    } else {
      _dio.options.headers['X-Device-Authorization'] = 'Device $deviceId:$tokenHex';
    }
  }

  Future<Map<String, dynamic>> getJson(
    String path, {
    Map<String, dynamic>? query,
  }) async {
    final response = await _send(() => _dio.get<dynamic>(path, queryParameters: _clean(query)));
    return _asMap(response);
  }

  Future<List<dynamic>> getList(
    String path, {
    Map<String, dynamic>? query,
  }) async {
    final response = await _send(() => _dio.get<dynamic>(path, queryParameters: _clean(query)));
    final data = response.data;
    if (data is List) return data;
    throw const ApiFailure('The server returned something unexpected.');
  }

  Future<Map<String, dynamic>> postJson(
    String path, {
    Object? body,
  }) async {
    final response = await _send(() => _dio.post<dynamic>(path, data: body == null ? null : jsonEncode(body)));
    return _asMap(response);
  }

  Future<void> postEmpty(String path, {Object? body}) async {
    await _send(() => _dio.post<dynamic>(path, data: body == null ? null : jsonEncode(body)));
  }

  Future<Map<String, dynamic>> patchJson(String path, {Object? body}) async {
    final response = await _send(() => _dio.patch<dynamic>(path, data: body == null ? null : jsonEncode(body)));
    return _asMap(response);
  }

  /// Run a request, converting anything thrown into an [ApiFailure].
  Future<Response<dynamic>> _send(Future<Response<dynamic>> Function() request) async {
    try {
      final response = await request();
      final status = response.statusCode ?? 0;
      if (status >= 500) {
        throw ApiFailure.fromDio(
          DioException(
            requestOptions: response.requestOptions,
            response: response,
            type: DioExceptionType.badResponse,
          ),
        );
      }
      if (status >= 400) {
        throw ApiFailure.fromDio(
          DioException(
            requestOptions: response.requestOptions,
            response: response,
            type: DioExceptionType.badResponse,
          ),
        );
      }
      return response;
    } on ApiFailure {
      rethrow;
    } on DioException catch (error) {
      throw ApiFailure.fromDio(error);
    } on FormatException {
      throw const ApiFailure('The server returned something unreadable.');
    }
  }

  Map<String, dynamic> _asMap(Response<dynamic> response) {
    final data = response.data;
    if (data is Map<String, dynamic>) return data;
    if (data is String && data.isNotEmpty) {
      final decoded = jsonDecode(data);
      if (decoded is Map<String, dynamic>) return decoded;
    }
    throw const ApiFailure('The server returned something unexpected.');
  }

  Map<String, dynamic>? _clean(Map<String, dynamic>? query) {
    if (query == null) return null;
    final cleaned = <String, dynamic>{};
    for (final entry in query.entries) {
      if (entry.value != null) cleaned[entry.key] = entry.value;
    }
    return cleaned.isEmpty ? null : cleaned;
  }
}
