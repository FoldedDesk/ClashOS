function main(config, profileName) {
  if (config.proxies[0].name !== 'Public added') throw new Error('PUBLIC sequence order is wrong');
  console.log('PUBLIC global', profileName);
  config.ipv6 = false;
  return config;
}
