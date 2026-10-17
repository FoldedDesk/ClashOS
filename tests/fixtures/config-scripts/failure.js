function main(config, profileName) {
  console.error('public failure fixture', profileName);
  throw new Error('public script failure');
}
