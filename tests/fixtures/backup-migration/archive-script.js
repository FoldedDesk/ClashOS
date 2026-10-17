function main(config, profileName) {
  config.hosts = config.hosts || {};
  config.hosts['backup.script.fixture.test'] = '192.0.2.61';
  config.rules = ['MATCH,REJECT'];
  console.info('backup archive global', profileName);
  return config;
}
