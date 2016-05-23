import { ItemzPage } from './app.po';

describe('itemz App', function() {
  let page: ItemzPage;

  beforeEach(() => {
    page = new ItemzPage();
  })

  it('should display message saying app works', () => {
    page.navigateTo();
    expect(page.getParagraphText()).toEqual('itemz works!');
  });
});
