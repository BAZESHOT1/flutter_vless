// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

#include "include/flutter_vless/flutter_vless_plugin.h"

#include <flutter/method_channel.h>
#include <flutter/event_channel.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <windows.h>
#include <memory>
#include <sstream>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <functional>
#include <vector>

#include "v2ray_manager.h"
#include <iostream>

namespace {

inline void LogMessage(const std::string& msg) {
  std::cout << "[FlutterVless] " << msg << std::endl;
  OutputDebugStringA(("[FlutterVless] " + msg + "\n").c_str());
}

class FlutterVlessPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  FlutterVlessPlugin(flutter::PluginRegistrarWindows *registrar);
  virtual ~FlutterVlessPlugin();

 private:
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  void StartStatusTimer();
  void StopStatusTimer();
  void UpdateStatus();
  void SendStatusToUI(const flutter::EncodableList& status);

  flutter::PluginRegistrarWindows *registrar_;
  std::unique_ptr<flutter::EventChannel<flutter::EncodableValue>> status_channel_;
  std::unique_ptr<flutter::EventSink<flutter::EncodableValue>> status_sink_;

  std::thread status_thread_;
  std::atomic<bool> is_running_{false};
  std::atomic<bool> should_stop_{false};

  std::mutex status_mutex_;
  std::mutex sink_mutex_;

  std::chrono::steady_clock::time_point start_time_;
  int64_t total_upload_ = 0;
  int64_t total_download_ = 0;
  int64_t upload_speed_ = 0;
  int64_t download_speed_ = 0;

  HWND main_window_handle_ = nullptr;
  int window_proc_delegate_id_ = 0;
  UINT ui_callback_message_id_ = 0;
  std::mutex ui_callbacks_mutex_;
  std::vector<std::function<void()>> ui_callbacks_;

  std::mutex lifecycle_mutex_;

  void RunOnUIThread(std::function<void()> callback) {
    {
      std::lock_guard<std::mutex> lock(ui_callbacks_mutex_);
      ui_callbacks_.push_back(std::move(callback));
    }
    if (main_window_handle_ && ui_callback_message_id_ != 0) {
      if (!PostMessage(main_window_handle_, ui_callback_message_id_, 0, 0)) {
        LogMessage("Error: PostMessage failed with error: " + std::to_string(GetLastError()));
      }
    } else {
      LogMessage("Warning: Cannot post to UI thread, window handle or message ID invalid");
    }
  }};

void FlutterVlessPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  auto plugin = std::make_unique<FlutterVlessPlugin>(registrar);
  registrar->AddPlugin(std::move(plugin));
}

FlutterVlessPlugin::FlutterVlessPlugin(flutter::PluginRegistrarWindows *registrar)
    : registrar_(registrar) {
  auto method_channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "flutter_vless",
          &flutter::StandardMethodCodec::GetInstance());

  method_channel->SetMethodCallHandler(
      [this](const auto &call, auto result) {
        HandleMethodCall(call, std::move(result));
      });

  status_channel_ =
      std::make_unique<flutter::EventChannel<flutter::EncodableValue>>(
          registrar->messenger(), "flutter_vless/status",
          &flutter::StandardMethodCodec::GetInstance());

  auto status_handler = std::make_unique<
      flutter::StreamHandlerFunctions<flutter::EncodableValue>>(
      [this](const flutter::EncodableValue *arguments,
             std::unique_ptr<flutter::EventSink<flutter::EncodableValue>> &&events)
          -> std::unique_ptr<flutter::StreamHandlerError<flutter::EncodableValue>> {
        LogMessage("EventChannel listener connected");
        {
          std::lock_guard<std::mutex> lock(sink_mutex_);
          status_sink_ = std::move(events);
        }

        if (status_sink_) {
          flutter::EncodableList initial_status;
          initial_status.push_back(flutter::EncodableValue("0"));
          initial_status.push_back(flutter::EncodableValue("0"));
          initial_status.push_back(flutter::EncodableValue("0"));
          initial_status.push_back(flutter::EncodableValue("0"));
          initial_status.push_back(flutter::EncodableValue("0"));
          initial_status.push_back(flutter::EncodableValue("DISCONNECTED"));

          LogMessage("Sending initial DISCONNECTED status");
          std::lock_guard<std::mutex> lock(sink_mutex_);
          if (status_sink_) {
            status_sink_->Success(flutter::EncodableValue(initial_status));
          }
        }

        return nullptr;
      },
      [this](const flutter::EncodableValue *arguments)
          -> std::unique_ptr<flutter::StreamHandlerError<flutter::EncodableValue>> {
        LogMessage("EventChannel listener disconnected");
        {
          std::lock_guard<std::mutex> lock(sink_mutex_);
          status_sink_.reset();
        }
        return nullptr;
      });

  status_channel_->SetStreamHandler(std::move(status_handler));

  if (registrar_) {
    auto view = registrar_->GetView();
    if (view) {
      main_window_handle_ = view->GetNativeWindow();
      if (main_window_handle_) {
        LogMessage("Main window handle obtained: " + std::to_string(reinterpret_cast<uintptr_t>(main_window_handle_)));
      } else {
        LogMessage("Warning: GetNativeWindow returned null");
      }
    } else {
      LogMessage("Warning: GetView returned null");
    }

    ui_callback_message_id_ = RegisterWindowMessageA("FLUTTER_VLESS_INVOKE_UI_CALLBACK");
    if (ui_callback_message_id_ == 0) {
      LogMessage("Error: Failed to register window message");
    } else {
      LogMessage("Window message ID registered: " + std::to_string(ui_callback_message_id_));
    }

    window_proc_delegate_id_ = registrar_->RegisterTopLevelWindowProcDelegate(
        [this](HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
            -> std::optional<LRESULT> {
          if (message == ui_callback_message_id_) {
            std::vector<std::function<void()>> tasks;
            {
              std::lock_guard<std::mutex> lock(ui_callbacks_mutex_);
              tasks.swap(ui_callbacks_);
            }
            LogMessage("Window proc delegate called for message " + std::to_string(message) + ", executing " + std::to_string(tasks.size()) + " tasks");
            for (auto &t : tasks) {
              try {
                t();
              } catch (const std::exception& e) {
                LogMessage("Exception in UI callback: " + std::string(e.what()));
              } catch (...) {
                LogMessage("Unknown exception in UI callback");
              }
            }
            return std::optional<LRESULT>(0);
          }
          return std::nullopt;
        });

    if (window_proc_delegate_id_ != 0) {
      LogMessage("Window proc delegate registered successfully");
    } else {
      LogMessage("Warning: Failed to register window proc delegate");
    }
  }

  LogMessage("Plugin initialized");
}

FlutterVlessPlugin::~FlutterVlessPlugin() {
  StopStatusTimer();
  V2rayManager::GetInstance().Stop();

  if (registrar_ && window_proc_delegate_id_ != 0) {
    registrar_->UnregisterTopLevelWindowProcDelegate(window_proc_delegate_id_);
    window_proc_delegate_id_ = 0;
  }
  {
    std::lock_guard<std::mutex> lock(sink_mutex_);
    status_sink_.reset();
  }
}

void FlutterVlessPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue> &method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  if (method_call.method_name().compare("requestPermission") == 0) {
    result->Success(flutter::EncodableValue(true));
  } else if (method_call.method_name().compare("initializeVless") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      LogMessage("initializeVless called");
      result->Success(flutter::EncodableValue(nullptr));
    } else {
      result->Error("INVALID_ARGUMENTS", "Invalid arguments for initializeVless");
    }
  } else if (method_call.method_name().compare("startVless") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      auto remark_it = arguments->find(flutter::EncodableValue("remark"));
      auto config_it = arguments->find(flutter::EncodableValue("config"));
      auto proxy_only_it = arguments->find(flutter::EncodableValue("proxy_only"));
      // >>> FLUTTER_VLESS_TUN
      auto use_xray_tun_it = arguments->find(flutter::EncodableValue("use_xray_tun"));
      // <<< FLUTTER_VLESS_TUN

      if (remark_it != arguments->end() && config_it != arguments->end()) {
        std::string remark = std::get<std::string>(remark_it->second);
        std::string config = std::get<std::string>(config_it->second);
        bool proxy_only = false;
        bool use_xray_tun = false;

        if (proxy_only_it != arguments->end()) {
          const auto* proxy_only_value = std::get_if<bool>(&proxy_only_it->second);
          if (proxy_only_value) {
            proxy_only = *proxy_only_value;
          }
        }

        // >>> FLUTTER_VLESS_TUN
        if (use_xray_tun_it != arguments->end()) {
          const auto* v = std::get_if<bool>(&use_xray_tun_it->second);
          if (v) use_xray_tun = *v;
        }
        LogMessage(std::string("startVless: proxy_only=") +
                   (proxy_only ? "true" : "false") +
                   ", use_xray_tun=" + (use_xray_tun ? "true" : "false"));
        // <<< FLUTTER_VLESS_TUN

        std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> shared_result = std::move(result);

        // >>> FLUTTER_VLESS_TUN: захватываем use_xray_tun
        std::thread([this, config, proxy_only, use_xray_tun, shared_result]() {
          std::lock_guard<std::mutex> lock(lifecycle_mutex_);
          LogMessage("Starting Xray...");
          if (V2rayManager::GetInstance().Start(config, proxy_only, use_xray_tun)) {
            LogMessage("Xray started successfully");
            is_running_ = true;
            start_time_ = std::chrono::steady_clock::now();
            StartStatusTimer();
          } else {
            LogMessage("Xray failed to start");
          }

          RunOnUIThread([shared_result]() {
            shared_result->Success(flutter::EncodableValue(nullptr));
          });
        }).detach();
        // <<< FLUTTER_VLESS_TUN

      } else {
        result->Error("INVALID_ARGUMENTS", "Missing remark or config");
      }
    } else {
      result->Error("INVALID_ARGUMENTS", "Invalid arguments for startVless");
    }
  } else if (method_call.method_name().compare("stopVless") == 0) {
    LogMessage("stopVless called");

    std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>> shared_result = std::move(result);

    std::thread([this, shared_result]() {
      std::lock_guard<std::mutex> lock(lifecycle_mutex_);

      StopStatusTimer();
      V2rayManager::GetInstance().Stop();
      is_running_ = false;
      total_upload_ = 0;
      total_download_ = 0;
      upload_speed_ = 0;
      download_speed_ = 0;

      flutter::EncodableList status;
      status.push_back(flutter::EncodableValue("0"));
      status.push_back(flutter::EncodableValue("0"));
      status.push_back(flutter::EncodableValue("0"));
      status.push_back(flutter::EncodableValue("0"));
      status.push_back(flutter::EncodableValue("0"));
      status.push_back(flutter::EncodableValue("DISCONNECTED"));

      SendStatusToUI(status);

      RunOnUIThread([shared_result]() {
        shared_result->Success(flutter::EncodableValue(nullptr));
      });
    }).detach();

  } else if (method_call.method_name().compare("getServerDelay") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      auto config_it = arguments->find(flutter::EncodableValue("config"));
      auto url_it = arguments->find(flutter::EncodableValue("url"));

      if (config_it != arguments->end() && url_it != arguments->end()) {
        std::string config = std::get<std::string>(config_it->second);
        std::string url = std::get<std::string>(url_it->second);

        std::thread([this, config, url, result = std::move(result)]() {
          int delay = V2rayManager::GetInstance().GetServerDelay(config, url);
          result->Success(flutter::EncodableValue(delay));
        }).detach();
        return;
      }
    }
    result->Error("INVALID_ARGUMENTS", "Invalid arguments for getServerDelay");
  } else if (method_call.method_name().compare("getConnectedServerDelay") == 0) {
    const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (arguments) {
      auto url_it = arguments->find(flutter::EncodableValue("url"));
      if (url_it != arguments->end()) {
        std::string url = std::get<std::string>(url_it->second);

        std::thread([this, url, result = std::move(result)]() {
          int delay = V2rayManager::GetInstance().GetConnectedServerDelay(url);
          result->Success(flutter::EncodableValue(delay));
        }).detach();
        return;
      }
    }
    result->Error("INVALID_ARGUMENTS", "Invalid arguments for getConnectedServerDelay");
  } else if (method_call.method_name().compare("getCoreVersion") == 0) {
    std::string version = V2rayManager::GetInstance().GetCoreVersion();
    LogMessage("getCoreVersion: " + version);
    result->Success(flutter::EncodableValue(version));
  } else if (method_call.method_name().compare("getProviderDebugSnapshot") == 0) {
    result->Success(flutter::EncodableValue(
        V2rayManager::GetInstance().GetProviderDebugSnapshot()));
  } else {
    result->NotImplemented();
  }
}

void FlutterVlessPlugin::StartStatusTimer() {
  should_stop_ = false;
  status_thread_ = std::thread([this]() {
    while (!should_stop_ && is_running_) {
      UpdateStatus();
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  });
}

void FlutterVlessPlugin::StopStatusTimer() {
  should_stop_ = true;
  if (status_thread_.joinable()) {
    status_thread_.join();
  }
}

void FlutterVlessPlugin::UpdateStatus() {
  {
    std::lock_guard<std::mutex> sink_lock(sink_mutex_);
    if (!status_sink_ || !is_running_) {
      return;
    }
  }

  std::lock_guard<std::mutex> status_lock(status_mutex_);

  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::seconds>(
      now - start_time_).count();

  int64_t current_upload = 0;
  int64_t current_download = 0;
  V2rayManager::GetInstance().GetTrafficStats(current_upload, current_download);

  upload_speed_ = current_upload - total_upload_;
  download_speed_ = current_download - total_download_;
  total_upload_ = current_upload;
  total_download_ = current_download;

  flutter::EncodableList status;
  status.push_back(flutter::EncodableValue(std::to_string(duration)));
  status.push_back(flutter::EncodableValue(std::to_string(upload_speed_)));
  status.push_back(flutter::EncodableValue(std::to_string(download_speed_)));
  status.push_back(flutter::EncodableValue(std::to_string(total_upload_)));
  status.push_back(flutter::EncodableValue(std::to_string(total_download_)));
  status.push_back(flutter::EncodableValue("CONNECTED"));

  LogMessage("UpdateStatus: duration=" + std::to_string(duration) + " up=" +
            std::to_string(upload_speed_) + " down=" + std::to_string(download_speed_));

  SendStatusToUI(status);
}

void FlutterVlessPlugin::SendStatusToUI(const flutter::EncodableList& status) {
  std::lock_guard<std::mutex> sink_lock(sink_mutex_);
  if (status_sink_) {
    try {
      std::string status_str = "[";
      for (size_t i = 0; i < status.size(); ++i) {
        if (i > 0) status_str += ", ";
        const auto& val = status[i];
        if (auto str_val = std::get_if<std::string>(&val)) {
          status_str += *str_val;
        } else {
          status_str += "?";
        }
      }
      status_str += "]";

      status_sink_->Success(flutter::EncodableValue(status));
      LogMessage("Status sent successfully: " + status_str);
    } catch (const std::exception& e) {
      LogMessage("Error sending status: " + std::string(e.what()));
    } catch (...) {
      LogMessage("Unknown error sending status");
    }
  } else {
    LogMessage("Warning: status_sink_ is null, cannot send status");
  }
}

}  // namespace

void FlutterVlessPluginRegisterWithRegistrar(
  flutter::PluginRegistrar* registrar) {
  FlutterVlessPlugin::RegisterWithRegistrar(
    reinterpret_cast<flutter::PluginRegistrarWindows*>(registrar));
}

void FlutterVlessPluginRegisterWithRegistrar(
  FlutterDesktopPluginRegistrarRef registrar) {
  FlutterVlessPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarManager::GetInstance()
      ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
