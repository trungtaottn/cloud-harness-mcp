import { expect, it } from 'vitest';
import { networkLabel } from './workspace-model';
it('distinguishes provider-managed network from restricted local profiles', () => {
  expect(networkLabel('provider-managed')).toBe('Provider-managed network');
  expect(networkLabel('dependency-access')).toBe('Dependency access');
  expect(networkLabel('network-none')).toBe('No network');
  expect(networkLabel('local-host')).toBe('Local host');
});
