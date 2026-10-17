function main(config, profileName) {
  config.hosts = config.hosts || {};
  config.hosts['backup.profile.fixture.test'] = profileName.includes('恢复') ? '192.0.2.63' : '192.0.2.62';
  return config;
}
