// Copyright 2011-2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/flags/flag.h"
#include "third_party/absl/flags/parse.h"
#include "third_party/absl/flags/usage.h"
#include "third_party/absl/flags/usage_config.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/absl/strings/str_split.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/zynamics/bindiff/config.h"
#include "third_party/zynamics/bindiff/version.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "third_party/zynamics/binexport/util/process.h"
#include "third_party/zynamics/binexport/util/status_macros.h"

ABSL_FLAG(std::string, config, "", "Config file name to use. Required");
ABSL_FLAG(bool, print_only, false,
          "Print final configuration to stdout and exit");
ABSL_FLAG(bool, help_settings, false,
          "Print the list of settings this tool can modify and exit");
ABSL_FLAG(bool, per_user, false,
          "Perform per-user setup of links to disassembler plugins");

namespace security::bindiff {

using ::security::binexport::GetLastOsError;
using ::security::binexport::GetOrCreateAppDataDirectory;

// File extension for shared libraries on supported platforms.
#if defined(_WIN32)
constexpr absl::string_view kLibrarySuffix = ".dll";
#elif defined(__APPLE__)
constexpr absl::string_view kLibrarySuffix = ".dylib";
#else
constexpr absl::string_view kLibrarySuffix = ".so";
#endif

absl::Status CreateOrUpdateDirectoryLink(const std::string& target,
                                         const std::string& link_path) {
#ifndef _WIN32
  // On Linux and macOS, simply create a symlink.
  return CreateOrUpdateLinkWithFallback(target, link_path);
#else
  // TODO(cblichmann): On Windows, we can do better than trying to create a
  //                   symlink by using directory junctions, which can be
  //                   created by regular users:
  // - CreateDirectories()
  // - OpenDirectory()
  // - Prepare a REPARSE_MOUNTPOINT_DATA_BUFFER
  // - DeviceIoControl(dir_handle, FSCTL_SET_REPARSE_POINT, ...)
  std::string canonical_target(MAX_PATH, '\0');
  if (!PathCanonicalize(&canonical_target[0], target.c_str()) ||
      !PathFileExists(canonical_target.c_str())) {
    return absl::FailedPreconditionError(
        absl::StrCat("Cannot read '", target, "': ", GetLastOsError()));
  }
  canonical_target.resize(strlen(canonical_target.c_str()));  // Right-trim NULs

  std::string canonical_path(MAX_PATH, '\0');
  if (!PathCanonicalize(&canonical_path[0], link_path.c_str())) {
    return absl::FailedPreconditionError(
        absl::StrCat("Path '", link_path, "' invalid: ", GetLastOsError()));
  }
  canonical_path.resize(strlen(canonical_path.c_str()));

  // Remove existing file first
  if (PathFileExists(canonical_path.c_str()) &&
      !DeleteFile(canonical_path.c_str())) {
    return absl::UnknownError(absl::StrCat(
        "Cannot remove existing '", canonical_path, "': ", GetLastOsError()));
  }
  if (CreateSymbolicLink(canonical_path.c_str(), canonical_target.c_str(),
                         SYMBOLIC_LINK_FLAG_DIRECTORY |
                             SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
    return absl::OkStatus();
  }
  return absl::UnknownError(absl::StrCat("Symlink '", canonical_target,
                                         "' to '", canonical_path,
                                         "' failed: ", GetLastOsError()));
#endif
}

absl::StatusOr<std::string> GetOrCreateIdaProUserPluginsDirectory() {
  std::string idapro_app_data;
#if defined(_WIN32)
  constexpr absl::string_view kIdaPro = R"(Hex-Rays\IDA Pro)";
  NA_ASSIGN_OR_RETURN(idapro_app_data, GetOrCreateAppDataDirectory(kIdaPro));
#elif defined(__APPLE__)
  // On macOS, IDA Pro stores its settings directly in the user's home folder
  // under ".idapro" instead of "Library/Application Support/idapro", which
  // is what GetOrCreateAppDataDirectory() would produce.
  constexpr absl::string_view kIdaPro = ".idapro";
  const char* home_dir = getenv("HOME");
  if (!home_dir) {
    return absl::NotFoundError("Home directory not set");
  }
  idapro_app_data = JoinPath(home_dir, kIdaPro);
#else
  constexpr absl::string_view kIdaPro = "idapro";
  NA_ASSIGN_OR_RETURN(idapro_app_data, GetOrCreateAppDataDirectory(kIdaPro));
#endif
  std::string idapro_app_data_plugin_path =
      JoinPath(idapro_app_data, "plugins");
  NA_RETURN_IF_ERROR(CreateDirectories(idapro_app_data_plugin_path));
  return idapro_app_data_plugin_path;
}

// Returns the path to Ghidra's per-user extension directory. Ghidra setings are
// stored in versioned directories, so the version argument should be of the
// form "10.2.2_PUBLIC".
absl::StatusOr<std::string> GetOrCreateGhidraUserExtensionsDirectory(
    absl::string_view version) {
  std::string ghidra_app_data;
#if defined(_WIN32)
  // On Windows, Ghidra stores its settings directory in the user profile folder
  // under ".ghidra" instead of "AppData/ghidra". This behavior is discouraged
  // and may eventually change.
  constexpr absl::string_view kGhidra = ".ghidra";

  char buffer[MAX_PATH] = {0};
  if (SHGetFolderPath(/*hwndOwner=*/0, CSIDL_PROFILE, /*hToken=*/0,
                      /*dwFlags=*/0, buffer) != S_OK) {
    return absl::UnknownError(GetLastOsError());
  }
  ghidra_app_data = JoinPath(buffer, kGhidra);
#elif defined(__APPLE__)
  // On macOS, Ghidra stores its settings directly in the user's home folder
  // under ".ghidra" instead of "Library/Application Support/ghidra", which
  // is what GetOrCreateAppDataDirectory() would produce.
  constexpr absl::string_view kGhidra = ".ghidra";
  const char* home_dir = getenv("HOME");
  if (!home_dir) {
    return absl::NotFoundError("Home directory not set");
  }
  ghidra_app_data = JoinPath(home_dir, kGhidra);
#else
  constexpr absl::string_view kGhidra = "ghidra";
  NA_ASSIGN_OR_RETURN(ghidra_app_data, GetOrCreateAppDataDirectory(kGhidra));
#endif

  std::string ghidra_app_data_extension_path = JoinPath(
      ghidra_app_data, absl::StrCat(".ghidra_", version), "Extensions");
  NA_RETURN_IF_ERROR(CreateDirectories(ghidra_app_data_extension_path));
  return ghidra_app_data_extension_path;
}

absl::Status MaybeSetupBinaryNinjaPerUser(absl::string_view bindiff_dir) {
#if defined(_WIN32)
  constexpr absl::string_view kBinaryNinja = "Binary Ninja";
  constexpr absl::string_view kBinDiffBinaryNinjaPluginsPrefix =
      R"(Plugins\Binary Ninja)";
#elif defined(__APPLE__)
  constexpr absl::string_view kBinaryNinja = "Binary Ninja";
  constexpr absl::string_view kBinDiffBinaryNinjaPluginsPrefix =
      "../../../Plugins/Binary Ninja";  // Relative to .app bundle
#else
  constexpr absl::string_view kBinaryNinja = "binaryninja";
  constexpr absl::string_view kBinDiffBinaryNinjaPluginsPrefix =
      "plugins/binaryninja";
#endif

  const std::string bindiff_binaryninja_plugins =
      JoinPath(bindiff_dir, kBinDiffBinaryNinjaPluginsPrefix);
  if (!IsDirectory(bindiff_binaryninja_plugins)) {
    // Binary Ninja may not have been selected during install.
    return absl::OkStatus();
  }

  NA_ASSIGN_OR_RETURN(const std::string binaryninja_app_data,
                      GetOrCreateAppDataDirectory(kBinaryNinja));
  const std::string binaryninja_app_data_plugin_path =
      JoinPath(binaryninja_app_data, "plugins");
  NA_RETURN_IF_ERROR(CreateDirectories(binaryninja_app_data_plugin_path));

  // BinExport only
  const std::string plugin_basename = absl::StrFormat(
      "binexport%s_binaryninja%s", kBinDiffBinExportRelease, kLibrarySuffix);
  return CreateOrUpdateLinkWithFallback(
      JoinPath(bindiff_binaryninja_plugins, plugin_basename),
      JoinPath(binaryninja_app_data_plugin_path, plugin_basename));
}

absl::Status SetupIdaProPerUser(absl::string_view bindiff_dir) {
#if defined(_WIN32)
  constexpr absl::string_view kBinDiffIdaProPluginsPrefix =
      R"(Plugins\IDA Pro)";
#elif defined(__APPLE__)
  constexpr absl::string_view kBinDiffIdaProPluginsPrefix =
      "../../../Plugins/IDA Pro";  // Relative to .app bundle
#else
  constexpr absl::string_view kBinDiffIdaProPluginsPrefix = "plugins/idapro";
#endif

  NA_ASSIGN_OR_RETURN(const std::string idapro_app_data_plugin_path,
                      GetOrCreateIdaProUserPluginsDirectory());
  NA_RETURN_IF_ERROR(CreateDirectories(idapro_app_data_plugin_path));

  // BinDiff itself
  std::string plugin_basename =
      absl::StrFormat("bindiff%s_ida%s", kBinDiffRelease, kLibrarySuffix);
  NA_RETURN_IF_ERROR(CreateOrUpdateLinkWithFallback(
      JoinPath(bindiff_dir, kBinDiffIdaProPluginsPrefix, plugin_basename),
      JoinPath(idapro_app_data_plugin_path, plugin_basename)));
  plugin_basename =
      absl::StrFormat("bindiff%s_ida64%s", kBinDiffRelease, kLibrarySuffix);
  NA_RETURN_IF_ERROR(CreateOrUpdateLinkWithFallback(
      JoinPath(bindiff_dir, kBinDiffIdaProPluginsPrefix, plugin_basename),
      JoinPath(idapro_app_data_plugin_path, plugin_basename)));

  // BinExport
  plugin_basename = absl::StrFormat("binexport%s_ida%s",
                                    kBinDiffBinExportRelease, kLibrarySuffix);
  NA_RETURN_IF_ERROR(CreateOrUpdateLinkWithFallback(
      JoinPath(bindiff_dir, kBinDiffIdaProPluginsPrefix, plugin_basename),
      JoinPath(idapro_app_data_plugin_path, plugin_basename)));
  plugin_basename = absl::StrFormat("binexport%s_ida64%s",
                                    kBinDiffBinExportRelease, kLibrarySuffix);
  NA_RETURN_IF_ERROR(CreateOrUpdateLinkWithFallback(
      JoinPath(bindiff_dir, kBinDiffIdaProPluginsPrefix, plugin_basename),
      JoinPath(idapro_app_data_plugin_path, plugin_basename)));
  return absl::OkStatus();
}

absl::Status MaybeSetupGhidraPerUser(absl::string_view bindiff_dir) {
#if defined(_WIN32)
  constexpr absl::string_view kBinDiffGhidraExtensionPrefix = R"(Extra\Ghidra)";
#elif defined(__APPLE__)
  constexpr absl::string_view kBinDiffGhidraExtensionPrefix =
      "../../../Extra/Ghidra";  // Relative to .app bundle
#else
  constexpr absl::string_view kBinDiffGhidraExtensionPrefix = "extra/ghidra";
#endif

  const std::string bindiff_ghidra_extensions =
      JoinPath(bindiff_dir, kBinDiffGhidraExtensionPrefix);
  if (!IsDirectory(bindiff_ghidra_extensions)) {
    // Ghidra may not have been selected during install.
    return absl::OkStatus();
  }

  for (absl::string_view version : {
           "10.3_PUBLIC",
       }) {
    NA_ASSIGN_OR_RETURN(const std::string ghidra_app_data_extensions_dir,
                        GetOrCreateGhidraUserExtensionsDirectory(version));
    NA_RETURN_IF_ERROR(CreateOrUpdateDirectoryLink(
        JoinPath(bindiff_dir, kBinDiffGhidraExtensionPrefix, "BinExport"),
        JoinPath(ghidra_app_data_extensions_dir, "BinExport")));
  }
  return absl::OkStatus();
}

// Sets up per-user configuration, creating links to the disassembler plugins.
// On Linux and macOS, always creates symlinks. On Windows, tries to create
// symlinks first, falling back to hardlinks/directory junctions and copying the
// files as a last resort.
absl::Status PerUserSetup(const Config& config) {
  const std::string& bindiff_dir = config.directory();
  if (bindiff_dir.empty()) {
    return absl::FailedPreconditionError(
        "Path to BinDiff missing from config file");
  }

  NA_RETURN_IF_ERROR(SetupIdaProPerUser(bindiff_dir));  // Always installed
  NA_RETURN_IF_ERROR(MaybeSetupBinaryNinjaPerUser(bindiff_dir));
  NA_RETURN_IF_ERROR(MaybeSetupGhidraPerUser(bindiff_dir));
  return absl::OkStatus();
}

using StringSettingsMap = absl::flat_hash_map<std::string, std::string*>;

absl::Status PrintSettingsNames(const StringSettingsMap& settings) {
  std::vector<std::string> names;
  names.reserve(settings.size());
  for (const auto& [key, unused] : settings) {
    names.push_back(key);
  }
  std::sort(names.begin(), names.end());
  for (const auto& name : names) {
    absl::PrintF("  %s\n", name);
  }
  return absl::OkStatus();
}

absl::Status ApplySettings(const std::vector<char*>& args,
                           const StringSettingsMap& settings) {
  for (const char* arg : args) {
    const std::pair<absl::string_view, absl::string_view> kv =
        absl::StrSplit(arg, absl::MaxSplits('=', 1));
    auto found = settings.find(kv.first);
    if (found == settings.end()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Invalid config setting: ", kv.first));
    }
    *found->second = kv.second;
  }
  return absl::OkStatus();
}

// Install Abseil Flags' library usage callbacks. This needs to be done before
// any operation that may call one of the callbacks.
void InstallFlagsUsageConfig() {
  absl::FlagsUsageConfig usage_config;
  usage_config.contains_help_flags = [](absl::string_view filename) {
    return !absl::StartsWith(filename, "core library");
  };
  usage_config.contains_helpshort_flags = usage_config.contains_help_flags;
  usage_config.version_string = []() {
    return absl::StrCat(kBinDiffName, " ", kBinDiffDetailedVersion, "\n");
  };
  usage_config.normalize_filename =
      [](absl::string_view filename) -> std::string {
    return absl::StartsWith(filename, "absl") ? "core library" : "this binary";
  };
  absl::SetFlagsUsageConfig(usage_config);
}

absl::Status ConfigSetupMain(int argc, char* argv[]) {
  const std::string binary_name = Basename(argv[0]);
  absl::SetProgramUsageMessage(
      absl::StrFormat("BinDiff config file servicing utility.\n"
                      "Usage: %1$s --config=FILE [KEY=VALUE]...\n"
                      "  or:  %1$s --per_user\n",
                      binary_name));
  InstallFlagsUsageConfig();
  std::vector<char*> positional = absl::ParseCommandLine(argc, argv);
  positional.erase(positional.begin());

  if (absl::GetFlag(FLAGS_per_user)) {
    if (argc != 2) {
      return absl::InvalidArgumentError("Extra arguments to `--per_user`");
    }
    return PerUserSetup(config::Proto());
  }

  // `print_only` loads the config file just like BinDiff itself does.
  auto config =
      !absl::GetFlag(FLAGS_print_only) ? config::Defaults() : config::Proto();

  const StringSettingsMap string_settings = {
      {"directory", config.mutable_directory()},
      {"ida.directory", config.mutable_ida()->mutable_directory()},
      {"log.directory", config.mutable_log()->mutable_directory()},
      {"preferences.default_workspace",
       config.mutable_preferences()->mutable_default_workspace()},
      {"ui.java_binary", config.mutable_ui()->mutable_java_binary()},
      {"ui.server", config.mutable_ui()->mutable_server()},
  };

  if (absl::GetFlag(FLAGS_help_settings)) {
    absl::PrintF("Available settings:\n");
    return PrintSettingsNames(string_settings);
  }

  const std::string config_filename = absl::GetFlag(FLAGS_config);
  if (config_filename.empty()) {
    if (!absl::GetFlag(FLAGS_print_only)) {
      return absl::InvalidArgumentError(
          "Missing config file argument, specify `--config`");
    }
  } else {
    NA_ASSIGN_OR_RETURN(auto loaded_config,
                        config::LoadFromFile(config_filename));
    config::MergeInto(loaded_config, config);
  }

  NA_RETURN_IF_ERROR(ApplySettings(positional, string_settings));

  const std::string serialized = config::AsJsonString(config);
  if (serialized.empty()) {
    return absl::InternalError("Serialization error");
  }

  // Print final config to stdout if requested
  if (absl::GetFlag(FLAGS_print_only)) {
    absl::PrintF("%s", serialized.c_str());
    return absl::OkStatus();
  }

  std::ofstream stream(config_filename,
                       std::ios::out | std::ios::trunc | std::ios::binary);
  stream.write(&serialized[0], serialized.size());
  stream.close();
  if (!stream) {
    return absl::UnknownError(
        absl::StrCat("I/O error writing file: ", GetLastOsError()));
  }
  return absl::OkStatus();
}

}  // namespace security::bindiff

int main(int argc, char** argv) {
  if (auto status = security::bindiff::ConfigSetupMain(argc, argv);
      !status.ok()) {
    absl::FPrintF(stderr, "Error: %s\n", status.message());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
