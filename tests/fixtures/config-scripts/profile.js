function main(config, profileName) {
  if (config.custom.stage !== 3) throw new Error('profile merge order lost');
  config.custom.stage = 4;
  config.custom.profileName = profileName;
  config.proxies.push({name: 'Script Direct', type: 'direct'});
  config['proxy-groups'].push({name: 'Script Policy', type: 'select', proxies: ['Script Direct', 'REJECT']});
  config.rules = ['DST-PORT,18088,Script Policy', 'MATCH,DIRECT'];
  config.hosts['profile.script.fixture.test'] = profileName.includes('-renamed') ? '192.0.2.51' : '192.0.2.50';
  if (profileName.endsWith('-busy')) config.port = 9090;
  console.warn('profile', profileName);
  return config;
}
