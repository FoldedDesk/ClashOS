constexpr size_t GEO_MAX_BYTES=64*1024*1024;
struct GeoIpSet {std::vector<RuleIpRange> ranges;bool inverse=false;};
struct GeoDomain {unsigned type=0;std::string value;std::set<std::string> attributes;};
struct GeoSiteMatcher {
    RuleDomainIndex domains;
    std::vector<std::string> keywords;
    std::vector<std::shared_ptr<ProviderPattern>> patterns;
    std::string error;
};
struct GeoDatabase {
    std::string kind;
    size_t bytes=0,count=0;
    std::map<std::string,GeoIpSet> ips;
    std::map<std::string,std::vector<GeoDomain>> sites;
    MMDB_s mmdb{};
    bool opened=false;
    mutable std::mutex matcherMutex;
    mutable std::map<std::string,std::shared_ptr<const GeoSiteMatcher>> matchers;
    ~GeoDatabase(){if(opened)MMDB_close(&mmdb);}
};
struct GeoResource {
    std::string kind,url,updatedAt,error;
    bool required=false,updating=false,forceUpdate=false,imported=false;
    uint64_t generation=0;
    HealthClock::time_point nextUpdate{};
    std::shared_ptr<const GeoDatabase> data;
};
struct GeoConfig {
    bool dat=false,autoUpdate=false;
    int interval=24;
    std::vector<GeoResource> resources{
        {"mmdb","https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/country.mmdb"},
        {"geoip","https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat"},
        {"geosite","https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat"},
        {"asn","https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/GeoLite2-ASN.mmdb"}};
};
bool geoTag(const std::string&);
using GeoSnapshots=std::map<std::string,std::shared_ptr<const GeoDatabase>>;
thread_local bool g_geoBootstrapDns=false;
bool parseGeoConfig(yaml_document_t&,yaml_node_t*,GeoConfig&,std::string&);
void initializeGeoLocked();
void refreshGeoRequirementsLocked();
GeoSnapshots geoSnapshotsLocked();
void geoLoop();
std::string geoControl(const std::string&,const std::string&,const std::string&);
