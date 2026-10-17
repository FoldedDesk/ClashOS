#include <dirent.h>

std::string networkBackupTestRequest(const std::string& source)
{
    ControllerConfigJson json; std::string error, operation, directory, value, expected, profile;
    if (!json.parse(source, error) || !json.string("operation", operation, error) || !json.string("directory", directory, error) ||
        !json.string("value", value, error) || !json.string("expected", expected, error) || !json.string("profile", profile, error)) throw std::runtime_error("Invalid public network test request");
    if (operation == "validate") return validateNetworkBackup(value);
    const auto slash = directory.find_last_of('/');
    if (slash == std::string::npos || !configureRuntimeDirectory(directory.substr(0, slash))) throw std::runtime_error("Cannot configure public network test request");
    if (operation == "snapshot") return networkBackupSnapshot(directory);
    if (operation == "restore") return restoreNetworkBackup(directory, value, expected, profile);
    throw std::runtime_error("Unknown public network test request");
}

void networkBackupTests(const std::string& directory)
{
    stopCore(); mkdir(directory.c_str(), 0700);
    const std::string profiles = directory + "/profiles", profile = profiles + "/public.yaml";
    mkdir(profiles.c_str(), 0700); require(configureRuntimeDirectory(directory), "Configure the owned application directory for network backup");
    auto snapshot = [&] { return networkBackupSnapshot(profiles); };
    auto revision = [&] { NetworkBackupSettings settings; std::array<std::string, 2> bytes; std::string error;
        require(readNetworkBackup(profiles, settings, bytes, error), "Read public preference fixtures"); return networkBackupRevision(networkBackupJson(settings)); };
    const std::string empty = "{\"version\":1,\"ports\":null,\"inbound\":null}";
    require(snapshot().find("\"settings\":" + empty) != std::string::npos, "Missing overrides have explicit null semantics");
    const std::string initial = revision(); require(initial.size() == 64, "Network snapshots have a bounded opaque comparison revision");
    const std::string inbound = "{\"allow-lan\":false,\"bind-address\":\"127.0.0.1\",\"authentication\":[\"backup-fixture:PUBLIC-p@ss:colon\"],\"skip-auth-prefixes\":[\"127.0.0.0/8\"],\"lan-allowed-ips\":[\"127.0.0.0/8\"],\"lan-disallowed-ips\":[]}";
    const std::string next = "{\"version\":1,\"ports\":{\"http\":18890,\"socks\":18891,\"mixed\":0},\"inbound\":" + inbound + "}";
    require(validateNetworkBackup(next).find("error") == std::string::npos, "A public complete network archive is accepted");
    require(restoreNetworkBackup(profiles, next, initial, "").find("\"applied\":false") != std::string::npos, "Offline restoration saves overrides without starting listeners");
    const auto saved = revision(); require(saved != initial && snapshot().find("PUBLIC-p@ss:colon") != std::string::npos, "The private snapshot retains complete proxy authentication for explicit backup");
    for (const auto& name : {".clashos-ports", ".clashos-inbound"}) {
        struct stat status{}; require(stat((profiles + "/" + name).c_str(), &status) == 0 && (status.st_mode & 0777) == 0600, "Saved network preferences are private regular files");
    }
    ProxyPortSettings ports; InboundConfig policy; bool overridden = false; std::string error;
    require(readProxyPortSettings(profile, ports, error) && ports.http == 18890 && ports.socks == 18891, "The normal startup port reader consumes restored bytes");
    require(readInboundSettings(profile, policy, overridden, error) && overridden && policy.users.size() == 1 && policy.users[0].second == "PUBLIC-p@ss:colon", "The normal startup authentication reader consumes restored bytes without truncating password colons");
    require(restoreNetworkBackup(profiles, empty, initial, "").find("error") != std::string::npos && revision() == saved, "A stale preview cannot replace newer saved preferences");
    const std::vector<std::string> invalid{
        "{}", "[]", "null", "{\"version\":1,\"ports\":null}", "{\"version\":2,\"ports\":null,\"inbound\":null}",
        "{\"version\":1,\"ports\":{},\"inbound\":null}",
        "{\"version\":1,\"ports\":{\"http\":\"7890\",\"socks\":7891,\"mixed\":0},\"inbound\":null}",
        "{\"version\":1,\"ports\":{\"http\":65536,\"socks\":7891,\"mixed\":0},\"inbound\":null}",
        "{\"version\":1,\"ports\":{\"http\":1.5,\"socks\":7891,\"mixed\":0},\"inbound\":null}",
        "{\"version\":1,\"ports\":null,\"inbound\":{\"authentication\":[\"PRIVATE-INVALID\"]}}",
        "{\"version\":1,\"ports\":null,\"inbound\":null,\"PRIVATE-INVALID\":true}"
    };
    for (const auto& value : invalid) {
        const auto checked = validateNetworkBackup(value), restored = restoreNetworkBackup(profiles, value, saved, "");
        require(checked.find("error") != std::string::npos && checked.find("PRIVATE-INVALID") == std::string::npos, "Invalid network fields are rejected without echoing archive values");
        require(restored.find("error") != std::string::npos && restored.find("PRIVATE-INVALID") == std::string::npos && revision() == saved, "Invalid restores preserve both saved files");
    }
    require(networkBackupSnapshot(directory).find("error") != std::string::npos, "Network backups cannot access an arbitrary directory");
    const std::string link = profiles + "/.clashos-inbound", original = link + ".original";
    require(rename(link.c_str(), original.c_str()) == 0 && symlink(original.c_str(), link.c_str()) == 0, "Create an owned symlink rejection control");
    require(snapshot().find("error") != std::string::npos && restoreNetworkBackup(profiles, empty, saved, "").find("error") != std::string::npos, "Preference symlinks cannot be read or replaced through backup");
    unlink(link.c_str()); require(rename(original.c_str(), link.c_str()) == 0, "Restore the public original preference file");
    // Exercise the live-state branch with all ingress disabled. Actual bind
    // conflict/traffic checks run on the emulator, not this listener-free suite.
    g_state.running.store(true); g_state.configPath = profile; g_state.temporaryConfig = false;
    const auto beforeRevision = g_state.configRevision;
    const std::string disabled = "{\"version\":1,\"ports\":{\"http\":0,\"socks\":0,\"mixed\":0},\"inbound\":" + inbound + "}";
    require(restoreNetworkBackup(profiles, disabled, saved, profile + ".different").find("error") != std::string::npos && revision() == saved, "A changed live profile rejects network restoration");
    const auto result = restoreNetworkBackup(profiles, disabled, saved, profile);
    require(result.find("\"applied\":true") != std::string::npos && g_state.httpPort == 0 && g_state.socksPort == 0 && g_state.configRevision > beforeRevision, "Live network bookkeeping commits together with the preference files");
    require(inboundStatusLocked().find("PUBLIC-p@ss:colon") == std::string::npos, "Public inbound status still never exports the restored password");
    g_state.running.store(false);
    require(restoreNetworkBackup(profiles, empty, revision(), "").find("error") == std::string::npos, "Explicit null restores profile-managed defaults");
    require(access((profiles + "/.clashos-ports").c_str(), F_OK) != 0 && access(link.c_str(), F_OK) != 0, "Default restoration removes both application override files");
    require(revision() == initial, "Restoring absent preferences produces the original comparison revision");
    DIR* entries = opendir(profiles.c_str()); require(entries != nullptr, "Inspect the owned preference directory");
    bool leftover = false; while (const auto* entry = readdir(entries)) if (std::string(entry->d_name).find(".network-") != std::string::npos) leftover = true; closedir(entries);
    require(!leftover, "Successful and rejected operations leave no private staging files");
}
