#ifndef V2RAY_MANAGER_H_
#define V2RAY_MANAGER_H_

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <optional>
#include <filesystem>
#include <chrono>
#include <future>
#include <map>
#include <cstdint>

#include "proxy_service.h"
#include "vpn_service.h"

namespace fs = std::filesystem;

class V2rayManager {
 public:
  static V2rayManager& GetInstance();

  // >>> FLUTTER_VLESS_TUN: добавлен use_xray_tun
  bool Start(const std::string& config, bool proxy_only, bool use_xray_tun = false);
  // <<< FLUTTER_VLESS_TUN
  void Stop();
  bool IsRunning() const;

  void GetTrafficStats(int64_t& upload, int64_t& download);

  std::future<int> GetServerDelayAsync(const std::string& config, const std::string& url);
  int GetServerDelay(const std::string& config, const std::string& url);
  int GetConnectedServerDelay(const std::string& url);

  std::string GetCoreVersion();

  std::string GetProviderDebugSnapshot();

 private:
  V2rayManager();
  ~V2rayManager();

  V2rayManager(const V2rayManager&) = delete;
  V2rayManager& operator=(const V2rayManager&) = delete;

  void RunV2ray();
  bool ValidateConfig(const std::string& config);
  std::string ModifyConfigForWindows(const std::string& config, bool proxy_only);

  std::atomic<bool> is_running_{false};
  std::thread v2ray_thread_;
  std::string current_config_;
  bool proxy_only_ = false;

  // >>> FLUTTER_VLESS_TUN: запоминаем режим
  bool use_xray_tun_ = false;
  // <<< FLUTTER_VLESS_TUN

  std::unique_ptr<ProxyService> proxy_service_;
  std::unique_ptr<VpnService> vpn_service_;
};

#endif  // V2RAY_MANAGER_H_
