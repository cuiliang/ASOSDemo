import {
  beforeEachProviders,
  it,
  describe,
  expect,
  inject
} from '@angular/core/testing';
import { SecurityService } from './security.service';

describe('Security Service', () => {
  beforeEachProviders(() => [SecurityService]);

  it('should ...',
      inject([SecurityService], (service: SecurityService) => {
    expect(service).toBeTruthy();
  }));
});
