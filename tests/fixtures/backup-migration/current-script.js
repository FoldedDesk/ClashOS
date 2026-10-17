function main(config, profileName) {
  config.hosts = config.hosts || {};
  config.hosts['backup.script.fixture.test'] = '192.0.2.71';
  config.rules = ['MATCH,DIRECT'];
  console.info('backup current global', profileName);
  return config;
}
