#include "vpn_service.h"
#include "diagnostics_log.h"
#include "xray_config.h"
#include "windows_network.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <wininet.h>
#include <process.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <algorithm>
#include <regex>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace {
std::optional<std::string> DefaultInterfaceName() {
  MIB_IF_ROW2 row{};
  if (GetBestInterface(0x08080808, &row.InterfaceIndex) != NO_ERROR ||
      GetIfEntry2(&row) != NO_ERROR) return std::nullopt;
  const int size = WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, nullptr, 0, nullptr, nullptr);
  if (size <= 1) return std::nullopt;
  std::string name(static_cast<size_t>(size), '\0');
  if (!WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, name.data(), size, nullptr, nullptr)) {
    return std::nullopt;
  }
  name.resize(static_cast<size_t>(size - 1));
  if (name == "flutter_vless_tun") return std::nullopt;
  return name;
}
bool WaitForTunnelAddress(const std::atomic<bool>& running) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
  while (running.load() && std::chrono::steady_clock::now() < deadline) {
    NET_LUID luid{};
    if (ConvertInterfaceAliasToLuid(L"flutter_vless_tun", &luid) == NO_ERROR) {
      MIB_UNICASTIPADDRESS_ROW address{};
      InitializeUnicastIpAddressEntry(&address);
      address.InterfaceLuid = luid;
      address.Address.Ipv4.sin_family = AF_INET;
      InetPtonA(AF_INET, "10.0.85.2", &address.Address.Ipv4.sin_addr);
      if (GetUnicastIpAddressEntry(&address) == NO_ERROR) {
        if (address.DadState == IpDadStatePreferred) return true;
        if (address.DadState == IpDadStateDuplicate) return false;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  return false;
}
}  // namespace

VpnService::VpnService() {
  xray_executable_path_ = FindXrayExecutable().value_or(fs::path());
  if (!xray_executable_path_.empty()) {
    std::cerr << "VpnService: Found Xray executable at: " << xray_executable_path_ << std::endl;
  } else {
    std::cerr << "VpnService: WARNING - Xray executable not found!" << std::endl;
  }

  tun2socks_executable_path_ = FindTun2SocksExecutable().value_or(fs::path());
  if (!tun2socks_executable_path_.empty()) {
    std::cerr << "VpnService: Found Tun2Socks executable at: " << tun2socks_executable_path_ << std::endl;
  } else {
    std::cerr << "VpnService: WARNING - Tun2Socks executable not found!" << std::endl;
  }
}

VpnService::~VpnService() {
  Stop();
  if (!temp_config_path_.empty() && fs::exists(temp_config_path_)) {
    try { fs::remove(temp_config_path_); } catch (...) {}
  }
}

bool VpnService::Start(const std::string& config) {
  Stop();

  current_config_ = config;
  use_xray_tun_ = false;

  if (xray_executable_path_.empty()) {
    std::cerr << "Xray executable not found." << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Xray executable not found for Windows VPN service");
    return false;
  }

  if (tun2socks_executable_path_.empty()) {
    std::cerr << "Tun2Socks executable not found." << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Tun2Socks executable not found for Windows VPN service");
    return false;
  }

  is_running_.store(true);
  vpn_thread_ = std::thread(&VpnService::RunVpn, this);

  return true;
}

// >>> FLUTTER_VLESS_TUN: новый режим — Xray сам создаёт TUN
bool VpnService::StartXrayTun(const std::string& config) {
  Stop();

  current_config_ = config;
  use_xray_tun_ = true;

  if (xray_executable_path_.empty()) {
    std::cerr << "VpnService: Xray executable not found for native TUN mode." << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Xray executable not found for Windows native TUN service");
    return false;
  }

  // В этом режиме tun2socks НЕ требуется: Xray сам создаёт TUN-адаптер
  // через wintun.dll и настраивает маршруты через autoSystemRoutingTable.
  is_running_.store(true);
  vpn_thread_ = std::thread(&VpnService::RunXrayTun, this);

  return true;
}

void VpnService::RunXrayTun() {
  // Просто записываем конфиг и запускаем Xray как есть.
  // Никаких InjectApiConfig / BindDirectOutbounds / netsh / route.
  fs::path config_path;
  if (!WriteConfigToFile(current_config_, config_path)) {
    std::cerr << "VpnService: Failed to write Xray TUN config" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to write Windows native TUN Xray configuration file");
    is_running_.store(false);
    return;
  }
  temp_config_path_ = config_path;

  if (!StartXrayProcess(config_path.string())) {
    std::cerr << "VpnService: Failed to start Xray for native TUN" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to start Windows native TUN Xray process");
    is_running_.store(false);
    return;
  }

  std::cerr << "VpnService: Xray native TUN mode started successfully" << std::endl;

  // Xray сам поднимет TUN и добавит маршруты через autoSystemRoutingTable.
  // Дадим ему несколько секунд на инициализацию.
  std::this_thread::sleep_for(std::chrono::seconds(5));

  // Запускаем сбор статистики (если в конфиге включён API stats).
  if (is_running_.load()) {
    stats_thread_ = std::thread(&VpnService::UpdateTrafficStats, this);
  }

  while (is_running_.load()) {
    if (xray_process_ && !xray_process_->IsRunning()) {
      std::cerr << "VpnService: Xray process exited unexpectedly (TUN mode)" << std::endl;
      flutter_vless::DiagnosticsLog::Instance().Append(
          "runtime", "Windows native TUN Xray process exited unexpectedly");
      is_running_.store(false);
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  StopProcesses();
}
// <<< FLUTTER_VLESS_TUN

void VpnService::Stop() {
  is_running_.store(false);

  if (vpn_thread_.joinable()) {
    vpn_thread_.join();
  }

  if (stats_thread_.joinable()) {
    stats_thread_.join();
  }

  StopProcesses();

  if (!temp_config_path_.empty() && fs::exists(temp_config_path_)) {
    try { fs::remove(temp_config_path_); } catch (...) {}
  }

  use_xray_tun_ = false;
}

bool VpnService::IsRunning() const {
  return is_running_.load();
}

void VpnService::RunVpn() {
  // ... (существующий код без изменений, как в оригинале)
  std::string config_with_api = InjectApiConfig(current_config_);
  const auto outbound_interface = DefaultInterfaceName();
  if (config_with_api.empty() || !outbound_interface ||
      !flutter_vless::xray_config::BindDirectOutbounds(config_with_api, *outbound_interface)) {
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Could not prepare Windows VPN configuration and direct interface");
    is_running_.store(false);
    return;
  }

  fs::path config_path;
  if (!WriteConfigToFile(config_with_api, config_path)) {
    std::cerr << "Failed to write Xray config for VPN" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to write Windows VPN Xray configuration file");
    is_running_.store(false);
    return;
  }
  temp_config_path_ = config_path;

  if (!StartXrayProcess(config_path.string())) {
    std::cerr << "Failed to start Xray for VPN" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to start Windows VPN Xray process");
    is_running_.store(false);
    return;
  }

  std::cerr << "VPN Service: Xray started successfully" << std::endl;
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  const auto selected_port = flutter_vless::xray_config::SocksPort(config_with_api);
  if (!selected_port) {
    StopProcesses();
    is_running_.store(false);
    return;
  }
  const uint16_t socks_port = *selected_port;
  std::cerr << "VPN Service: Xray SOCKS port detected as " << socks_port << std::endl;

  if (!StartTun2SocksProcess(socks_port)) {
    std::cerr << "Failed to start Tun2Socks" << std::endl;
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Failed to start Windows VPN Tun2Socks process");
    StopProcesses();
    is_running_.store(false);
    return;
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(2000));

  if (!xray_process_->IsRunning() || !tun2socks_process_->IsRunning()) {
    flutter_vless::DiagnosticsLog::Instance().Append(
        "runtime", "Windows VPN worker exited before network configuration");
    StopProcesses();
    is_running_.store(false);
    return;
  }

  std::cerr << "VPN Service: Configuring TUN interface..." << std::endl;

  std::string set_ip_cmd = "netsh interface ip set address name=\"flutter_vless_tun\" source=static addr=10.0.85.2 mask=255.255.255.0 gateway=none";
  if (system(set_ip_cmd.c_str()) != 0) {
    flutter_vless::DiagnosticsLog::Instance().Append("runtime", "Failed to configure Windows TUN address");
    StopProcesses();
    is_running_.store(false);
    return;
  }

  if (!WaitForTunnelAddress(is_running_)) {
    flutter_vless::DiagnosticsLog::Instance().Append("runtime", "Windows TUN IPv4 address did not become ready");
    StopProcesses();
    is_running_.store(false);
    return;
  }

  std::string server_address = ExtractServerAddress(current_config_);
  if (!server_address.empty()) {
    std::string server_ip = ResolveToIP(server_address);
    if (!server_ip.empty()) {
      std::string default_gateway = GetDefaultGateway();
      if (!default_gateway.empty()) {
        std::string delete_bypass_route_cmd = "route DELETE " + server_ip;
        system(delete_bypass_route_cmd.c_str());
        std::string bypass_route_cmd = "route ADD " + server_ip + " MASK 255.255.255.255 " + default_gateway + " METRIC 1";
        system(bypass_route_cmd.c_str());

        system("route DELETE 8.8.8.8");
        system("route DELETE 1.1.1.1");

        std::string dns1_route_cmd = "route ADD 8.8.8.8 MASK 255.255.255.255 " + default_gateway + " METRIC 1";
        std::string dns2_route_cmd = "route ADD 1.1.1.1 MASK 255.255.255.255 " + default_gateway + " METRIC 1";
        system(dns1_route_cmd.c_str());
        system(dns2_route_cmd.c_str());
      }
    }
  }

  for (const auto* prefix : {"0.0.0.0/1", "128.0.0.0/1"}) {
    const std::string command = "netsh interface ipv4 add route " + std::string(prefix) +
        " \"flutter_vless_tun\" 10.0.85.1 metric=1 store=active";
    if (system(command.c_str()) != 0) {
      flutter_vless::DiagnosticsLog::Instance().Append("runtime", "Failed to install Windows VPN capture route");
      StopProcesses();
      is_running_.store(false);
      return;
    }
    capture_routes_.push_back(prefix);
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  std::string dns_cmd1 = "netsh interface ipv4 set dns name=\"flutter_vless_tun\" static 8.8.8.8 primary validate=no";
  std::string dns_cmd2 = "netsh interface ipv4 add dns name=\"flutter_vless_tun\" 1.1.1.1 index=2 validate=no";
  system(dns_cmd1.c_str());
  system(dns_cmd2.c_str());

  std::cerr << "VPN Service: TUN interface configured and capture routes added" << std::endl;

  stats_thread_ = std::thread(&VpnService::UpdateTrafficStats, this);

  while (is_running_.load()) {
    if (xray_process_ && !xray_process_->IsRunning()) {
      std::cerr << "Xray process exited unexpectedly" << std::endl;
      flutter_vless::DiagnosticsLog::Instance().Append(
          "runtime", "Windows VPN Xray process exited unexpectedly");
      is_running_.store(false);
      break;
    }
    if (tun2socks_process_ && !tun2socks_process_->IsRunning()) {
      std::cerr << "Tun2Socks process exited unexpectedly" << std::endl;
      flutter_vless::DiagnosticsLog::Instance().Append(
          "runtime", "Windows VPN Tun2Socks process exited unexpectedly");
      is_running_.store(false);
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  StopProcesses();
}

// Остальные методы StartXrayProcess, StartTun2SocksProcess, StopProcesses,
// InjectApiConfig, RunXrayApiCommand, GetTrafficStats, UpdateTrafficStats,
// WriteConfigToFile, FindXrayExecutable, FindTun2SocksExecutable,
// FindXrayAssets, ExtractServerAddress, ResolveToIP, GetDefaultGateway
// ОСТАЮТСЯ БЕЗ ИЗМЕНЕНИЙ (копируй из оригинала).
// Единственное: в StopProcesses добавь сброс use_xray_tun_ = false; (опционально).
