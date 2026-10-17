function main(config, profileName) {
  console.log(profileName);
  config.ipv6 = false;
  config.hosts = {publicScript: String.fromCharCode(49,57,50,46,48,46,50,46,50,53)};
  return config;
}
