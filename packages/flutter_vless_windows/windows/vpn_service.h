#ifndef VPN_SERVICE_H_
#define VPN_SERVICE_H_

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <filesystem>
#include <optional>
#include <vector>

#include "proxy_service.h"

namespace fs = std::filesystem;

class VpnService {
 public:
  VpnService();
  ~VpnService();

  bool Start(const std::string& config);

  // >>> FLUTTER_VLESS_TUN: новый режим — нативный Xray TUN
  bool StartXrayTun(const std::string& config);
  // <<< FLUTTER_VLESS_TUN

  void Stop();
  bool IsRunning() const;

  void GetTrafficStats(int64_t& upload, int64_t& download);

 private:
  void RunVpn();

  // >>> FLUTTER_VLESS_TUN: отдельный цикл для Xray TUN
  void RunXrayTun();
  // <<< FLUTTER_VLESS_TUN

  bool StartXrayProcess(const std::string& config_path);
  bool StartTun2SocksProcess(uint16_t socks_port);
  void StopProcesses();

  void UpdateTrafficStats();
  bool RunXrayApiCommand(const std::string& args, std::string& output);
  std::string InjectApiConfig(const std::string& config);

  bool WriteConfigToFile(const std::string& config, fs::path& config_path);
  std::optional<fs::path> FindTun2SocksExecutable();
  std::optional<fs::path> FindXrayExecutable();
  std::optional<fs::path> FindXrayAssets(const fs::path& executable_path);

  std::string ExtractServerAddress(const std::string& config);
  std::string ResolveToIP(const std::string& address);
  std::string GetDefaultGateway();

  std::atomic<bool> is_running_{false};
  std::thread vpn_thread_;
  std::thread stats_thread_;

  std::unique_ptr<ProcessHandle> xray_process_;
  std::unique_ptr<ProcessHandle> tun2socks_process_;

  fs::path xray_executable_path_;
  fs::path tun2socks_executable_path_;
  fs::path temp_config_path_;

  std::string current_config_;
  std::vector<std::string> capture_routes_;

  // >>> FLUTTER_VLESS_TUN: флаг режима
  bool use_xray_tun_ = false;
  // <<< FLUTTER_VLESS_TUN

  std::mutex stats_mutex_;
  int64_t total_upload_ = 0;
  int64_t total_download_ = 0;
  std::string api_address_ = "127.0.0.1:10086";
};

#endif // VPN_SERVICE_H_
