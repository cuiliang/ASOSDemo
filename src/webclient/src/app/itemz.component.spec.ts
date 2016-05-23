import {
  beforeEachProviders,
  describe,
  expect,
  it,
  inject
} from '@angular/core/testing';
import { ItemzAppComponent } from '../app/itemz.component';

beforeEachProviders(() => [ItemzAppComponent]);

describe('App: Itemz', () => {
  it('should create the app',
      inject([ItemzAppComponent], (app: ItemzAppComponent) => {
    expect(app).toBeTruthy();
  }));

  it('should have as title \'itemz works!\'',
      inject([ItemzAppComponent], (app: ItemzAppComponent) => {
    expect(app.title).toEqual('itemz works!');
  }));
});
