#include "v2ray_manager.h"
#include "diagnostics_log.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <process.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <algorithm>
#include <regex>
#include <map>
#include <vector>
#include <cstring>
#include <string>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")

namespace {
namespace json_utils {
  bool IsValidJson(const std::string& json_str) {
    int brace_count = 0;
    int bracket_count = 0;
    bool in_string = false;
    bool escaped = false;

    for (char c : json_str) {
      if (escaped) {
        escaped = false;
        continue;
      }

      if (c == '\\') {
        escaped = true;
        continue;
      }

      if (c == '"') {
        in_string = !in_string;
        continue;
      }

      if (in_string) continue;

      if (c == '{') brace_count++;
      else if (c == '}') brace_count--;
      else if (c == '[') bracket_count++;
      else if (c == ']') bracket_count--;

      if (brace_count < 0 || bracket_count < 0) return false;
    }

    return brace_count == 0 && bracket_count == 0 && !in_string;
  }
}
}

V2rayManager::V2rayManager() {
  proxy_service_ = std::make_unique<ProxyService>();
  vpn_service_ = std::make_unique<VpnService>();
}

V2rayManager::~V2rayManager() {
  Stop();
}

V2rayManager& V2rayManager::GetInstance() {
  static V2rayManager instance;
  return instance;
}

// >>> FLUTTER_VLESS_TUN: реализация с use_xray_tun
bool V2rayManager::Start(const std::string& config, bool proxy_only, bool use_xray_tun) {
  if (is_running_.load()) {
    Stop();
  }

  flutter_vless::DiagnosticsLog::Instance().Reset();
  flutter_vless::DiagnosticsLog::Instance().Append(
      "runtime",
      use_xray_tun ? "Starting Windows native Xray TUN session"
                   : (proxy_only ? "Starting Windows proxy-only session"
                                 : "Starting Windows VPN (tun2socks) session"));

  if (!ValidateConfig(config)) {
    std::cerr << "Invalid Xray configuration JSON" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Invalid Xray configuration JSON");
    return false;
  }

  current_config_ = config;
  proxy_only_ = proxy_only;
  use_xray_tun_ = use_xray_tun;

  // НОВЫЙ РЕЖИМ: нативный Xray TUN.
  // В этом режиме мы НЕ используем tun2socks и НЕ трогаем маршруты вручную —
  // Xray сам создаст TUN и добавит маршруты через autoSystemRoutingTable.
  if (use_xray_tun_) {
    if (!vpn_service_) {
      flutter_vless::DiagnosticsLog::Instance().Append(
          "runtime", "VpnService is not initialized");
      return false;
    }
    is_running_.store(true);
    if (!vpn_service_->StartXrayTun(config)) {
      is_running_.store(false);
      return false;
    }
    return true;
  }

  if (proxy_only_) {
    if (proxy_service_) {
      is_running_.store(true);
      return proxy_service_->Start(config);
    }
    return false;
  } else {
    std::cerr << "Starting VPN mode with Tun2Socks..." << std::endl;
    if (vpn_service_) {
      is_running_.store(true);
      return vpn_service_->Start(config);
    }
    return false;
  }
}
// <<< FLUTTER_VLESS_TUN

void V2rayManager::Stop() {
  if (!is_running_.load()) {
    return;
  }

  is_running_.store(false);

  // >>> FLUTTER_VLESS_TUN: если это был режим Xray TUN — останавливаем его
  if (use_xray_tun_) {
    if (vpn_service_) {
      vpn_service_->Stop();
    }
    use_xray_tun_ = false;
    return;
  }
  // <<< FLUTTER_VLESS_TUN

  if (proxy_only_) {
    if (proxy_service_) {
      proxy_service_->Stop();
    }
  } else {
    if (vpn_service_) {
      vpn_service_->Stop();
    }
  }
}

bool V2rayManager::IsRunning() const {
  if (use_xray_tun_) {
    return is_running_.load() && vpn_service_ && vpn_service_->IsRunning();
  }
  return is_running_.load() && (proxy_only_
      ? (proxy_service_ && proxy_service_->IsRunning())
      : (vpn_service_ && vpn_service_->IsRunning()));
}

void V2rayManager::RunV2ray() {
  std::cerr << "VPN functionality is currently disabled. Printing to console only." << std::endl;

  while (is_running_.load()) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

std::future<int> V2rayManager::GetServerDelayAsync(const std::string& config, const std::string& url) {
  return std::async(std::launch::async, [this, config, url]() {
    return GetServerDelay(config, url);
  });
}

int V2rayManager::GetServerDelay(const std::string& config, const std::string& url) {
  if (proxy_service_) {
    return proxy_service_->MeasureDelayStateless(config, url);
  }
  return -1;
}

int V2rayManager::GetConnectedServerDelay(const std::string& url) {
  if (proxy_only_ && proxy_service_) {
    return proxy_service_->GetServerDelay(url);
  }
  return -1;
}

std::string V2rayManager::GetCoreVersion() {
  if (proxy_service_) {
    return proxy_service_->GetCoreVersion();
  }
  return "Unknown";
}

std::string V2rayManager::GetProviderDebugSnapshot() {
  return flutter_vless::DiagnosticsLog::Instance().Snapshot();
}

void V2rayManager::GetTrafficStats(int64_t& upload, int64_t& download) {
  if (use_xray_tun_) {
    if (vpn_service_) {
      vpn_service_->GetTrafficStats(upload, download);
    } else {
      upload = 0;
      download = 0;
    }
    return;
  }

  if (proxy_only_) {
    if (proxy_service_) {
      proxy_service_->GetTrafficStats(upload, download);
    } else {
      upload = 0;
      download = 0;
    }
  } else {
    if (vpn_service_) {
      vpn_service_->GetTrafficStats(upload, download);
    } else {
      upload = 0;
      download = 0;
    }
  }
}

bool V2rayManager::ValidateConfig(const std::string& config) {
  return json_utils::IsValidJson(config);
}

std::string V2rayManager::ModifyConfigForWindows(const std::string& config, bool proxy_only) {
  return config;
}
