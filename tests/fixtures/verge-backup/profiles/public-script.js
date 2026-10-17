function main(config, profileName) {
  console.log('PUBLIC profile', profileName);
  config.hosts = Object.assign({}, config.hosts, {'public-profile.invalid': '192.0.2.101'});
  config.rules.unshift('DOMAIN,script-public.invalid,DIRECT');
  return config;
}
