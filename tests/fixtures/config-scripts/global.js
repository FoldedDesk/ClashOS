function main(config, profileName) {
  if (config.custom.stage !== 1 || config.values.enabled !== true ||
      config.values.count !== 7 || config.values.code !== '00123') {
    throw new Error('global merge order or scalar types lost');
  }
  config.custom.stage = 2;
  config.rules = ['MATCH,REJECT'];
  config.hosts = {'global.script.fixture.test': '192.0.2.40'};
  console.info('global', profileName);
  return config;
}
