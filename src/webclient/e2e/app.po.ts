export class ItemzPage {
  navigateTo() {
    return browser.get('/');
  }

  getParagraphText() {
    return element(by.css('itemz-app h1')).getText();
  }
}
