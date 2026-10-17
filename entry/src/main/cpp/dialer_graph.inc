// Pure configuration validation. Include provider members after their filters,
// overrides and name prefixes; never consult or mutate a running route here.
bool validateDialerGraph(const std::vector<ProxyNode>& local, const std::vector<ProxyProvider>& providers,
    const std::vector<ProxyGroup>& groups, std::string& error, bool deferMissing = false)
{
    std::map<std::string, const ProxyNode*> nodes;
    for (const auto& node : local) nodes[node.name] = &node;
    for (const auto& provider : providers) for (const auto& node : provider.nodes) nodes[node.name] = &node;
    if (std::none_of(nodes.begin(), nodes.end(), [](const auto& item) { return !item.second->dialerProxy.empty(); })) return true;
    std::map<std::string, std::vector<std::string>> edges;
    for (const auto& item : nodes) {
        if (item.second->type == "reject" && !item.second->dialerProxy.empty()) { error = "REJECT nodes cannot use dialer-proxy"; return false; }
        if (!item.second->dialerProxy.empty()) edges[item.first].push_back(item.second->dialerProxy);
    }
    size_t work = 0;
    for (const auto& group : groups) {
        auto members = group.configuredProxies;
        if (members.empty() && group.providers.empty() && !group.includeAllProxies && !group.includeAllProviders) members = group.proxies;
        std::set<std::string> seen(members.begin(), members.end()); ProviderPattern include(group.filter), exclude(group.excludeFilter);
        auto add = [&](const ProxyNode& node) {
            if (++work > 200000) return false;
            if (include.matches(node.name) && (group.excludeFilter.empty() || !exclude.matches(node.name)) && seen.insert(node.name).second) members.push_back(node.name);
            return true;
        };
        if (group.includeAllProxies) for (const auto& node : local) if (!add(node)) { error = "Proxy chain graph exceeds its complexity limit"; return false; }
        for (const auto& provider : providers)
            if (group.includeAllProviders || std::find(group.providers.begin(), group.providers.end(), provider.name) != group.providers.end())
                for (const auto& node : provider.nodes) if (!add(node)) { error = "Proxy chain graph exceeds its complexity limit"; return false; }
        if (!group.excludeFilter.empty()) members.erase(std::remove_if(members.begin(), members.end(), [&](const auto& name) { return exclude.matches(name); }), members.end());
        work += members.size(); if (work > 200000) { error = "Proxy chain graph exceeds its complexity limit"; return false; }
        edges[group.name] = std::move(members);
    }
    std::map<std::string, int> color, height, span;
    std::set<std::string> groupNames; for (const auto& group : groups) groupNames.insert(group.name);
    std::function<bool(const std::string&, int)> visit = [&](const std::string& name, int depth) {
        if (depth >= 64) { error = "Proxy chain contains excessive group nesting"; return false; }
        if (name == "DIRECT" || name == "REJECT") { span[name] = 1; return true; }
        if (!nodes.count(name) && !groupNames.count(name)) {
            if (deferMissing) { span[name] = 1; return true; }
            error = "dialer-proxy refers to an unavailable proxy/group"; return false;
        }
        if (color[name] == 1) { error = "Proxy chain contains a circular reference"; return false; }
        if (color[name] == 2) {
            if (depth + span[name] <= 64) return true;
            error = "Proxy chain contains excessive group nesting"; return false;
        }
        color[name] = 1; height[name] = nodes.count(name) ? 1 : 0;
        int children = 0; span[name] = 1;
        for (const auto& child : edges[name]) { if (!visit(child, depth + 1)) return false; children = std::max(children, height[child]); span[name] = std::max(span[name], 1 + span[child]); }
        height[name] += children;
        if (height[name] > 8) { error = "Proxy chains support at most eight outbound nodes"; return false; }
        color[name] = 2; return true;
    };
    for (const auto& item : nodes) if (!item.second->dialerProxy.empty() && !visit(item.first, 0)) return false;
    return true;
}
