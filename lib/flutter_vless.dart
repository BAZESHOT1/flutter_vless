// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

import 'dart:convert';

import 'package:flutter_vless/url/hysteria2.dart';
import 'package:flutter_vless/url/shadowsocks.dart';
import 'package:flutter_vless/url/socks.dart';
import 'package:flutter_vless/url/subscription.dart';
import 'package:flutter_vless/url/trojan.dart';
import 'package:flutter_vless/url/url.dart';
import 'package:flutter_vless/url/vless.dart';
import 'package:flutter_vless/url/vmess.dart';
import 'package:flutter_vless/url/xray_config.dart';
import 'package:flutter_vless/url/xray_config_model.dart';
import 'package:flutter_vless/url/xray_config_validator.dart';
import 'package:flutter_vless_platform_interface/flutter_vless_platform_interface.dart';

export 'package:flutter_vless_platform_interface/flutter_vless_platform_interface.dart';
export 'url/url.dart';

class FlutterVless {
  FlutterVless({required this.onStatusChanged});

  static const XrayConfigValidator _configValidator = XrayConfigValidator();

  final void Function(VlessStatus status) onStatusChanged;

  Future<bool> requestPermission() {
    return VlessPlatform.instance.requestPermission();
  }

  Future<void> initializeVless({
    String notificationIconResourceType = "mipmap",
    String notificationIconResourceName = "ic_launcher",
    String providerBundleIdentifier = "",
    String groupIdentifier = "",
  }) async {
    await VlessPlatform.instance.initializeVless(
      onStatusChanged: onStatusChanged,
      notificationIconResourceType: notificationIconResourceType,
      notificationIconResourceName: notificationIconResourceName,
      providerBundleIdentifier: providerBundleIdentifier,
      groupIdentifier: groupIdentifier,
    );
  }

  // >>> FLUTTER_VLESS_TUN: добавлен useXrayTun
  /// Starts an Xray-backed proxy or VPN/tunnel session.
  ///
  /// [useXrayTun] включает нативный TUN-inbound Xray (Windows-only).
  /// В этом режиме плагин НЕ использует tun2socks и НЕ настраивает маршруты
  /// вручную — Xray сам создаёт TUN-адаптер (через wintun.dll) и добавляет
  /// маршруты через `autoSystemRoutingTable` в конфиге. Переданный [config]
  /// должен уже содержать TUN-inbound и rules с `process`.
  ///
  /// Игнорируется на платформах, отличных от Windows.
  Future<void> startVless({
    required String remark,
    required String config,
    List<String>? blockedApps,
    List<String>? bypassSubnets,
    bool proxyOnly = false,
    bool useXrayTun = false, // >>> FLUTTER_VLESS_TUN
    String? geoAssetsDirectory,
    String notificationDisconnectButtonName = "DISCONNECT",
  }) async {
    final normalizedConfig = _normalizeConfigString(config);

    await VlessPlatform.instance.startVless(
      remark: remark,
      config: normalizedConfig,
      blockedApps: blockedApps,
      proxyOnly: proxyOnly,
      // >>> FLUTTER_VLESS_TUN: прокидываем параметр через MethodChannel напрямую,
      // т.к. platform_interface может его не знать.
      useXrayTun: useXrayTun,
      // <<< FLUTTER_VLESS_TUN
      bypassSubnets: bypassSubnets,
      geoAssetsDirectory: geoAssetsDirectory,
      notificationDisconnectButtonName: notificationDisconnectButtonName,
    );
  }
  // <<< FLUTTER_VLESS_TUN

  Future<void> stopVless() async {
    await VlessPlatform.instance.stopVless();
  }

  Future<int> getServerDelay(
      {required String config,
      String url = 'https://google.com/generate_204',
      String? geoAssetsDirectory}) async {
    final normalizedConfig = _normalizeConfigString(config);
    return await VlessPlatform.instance.getServerDelay(
      config: normalizedConfig,
      url: url,
      geoAssetsDirectory: geoAssetsDirectory,
    );
  }

  Future<int> getConnectedServerDelay(
      {String url = 'https://google.com/generate_204'}) async {
    return await VlessPlatform.instance.getConnectedServerDelay(url);
  }

  Future<String> getCoreVersion() async {
    return await VlessPlatform.instance.getCoreVersion();
  }

  Future<String> getProviderDebugSnapshot() async {
    return await VlessPlatform.instance.getProviderDebugSnapshot();
  }

  static FlutterVlessURL parse(String input) {
    final trimmed = input.trim();
    if (_isSingleShareLink(trimmed)) {
      return parseFromURL(trimmed);
    }
    return parseMany(trimmed).first;
  }

  static List<FlutterVlessURL> parseMany(String input) {
    return VlessSubscriptionParser.parseMany(
      input: input,
      parseUrl: parseFromURL,
      parseJson: (json) => XrayJsonConfig(url: json),
    );
  }

  static FlutterVlessURL parseFromURL(String url) {
    switch (url.split("://")[0].toLowerCase()) {
      case 'vmess':
        return VmessURL(url: url);
      case 'vless':
        return VlessURL(url: url);
      case 'trojan':
        return TrojanURL(url: url);
      case 'ss':
        return ShadowSocksURL(url: url);
      case 'socks':
        return SocksURL(url: url);
      case 'hysteria2':
      case 'hy2':
        return Hysteria2URL(url: url);
      default:
        throw ArgumentError('url is invalid');
    }
  }

  static bool _isSingleShareLink(String input) {
    if (input.contains('\n') || input.contains('\r')) {
      return false;
    }
    final separator = input.indexOf('://');
    if (separator <= 0) {
      return false;
    }
    return const {'vmess', 'vless', 'trojan', 'ss', 'socks', 'hysteria2', 'hy2'}
        .contains(input.substring(0, separator).toLowerCase());
  }

  static String _normalizeConfigString(String config) {
    final decoded = _configValidator.validateJsonString(config);
    return jsonEncode(sanitizeXrayJson(decoded));
  }
}
