import { Injectable } from '@angular/core';
import {JwtHelper, tokenNotExpired} from 'angular2-jwt';
import 'rxjs/add/operator/map';
// import {Observable} from 'rxjs/Observable';
import {AppConfiguration} from '../app.configuration';
import {Router} from '@angular/router';

/**
 * 用户登录处理
 */
@Injectable()
export class SecurityService {

  private storage: Storage;

  private _accessTokenStorageKey: string = 'access_token';
  private _idTokenStorageKey: string = 'id_token';
  private _keys = {

    'authStateControl': 'authStateControl',
    'authNonce': 'authNonce'
  };

  constructor(private _config: AppConfiguration,
    private router: Router) {
    this.storage = localStorage;

  }

  /**
   * 用户是否已登录
   */
  public isAuthroized(): boolean {
    return tokenNotExpired(this._idTokenStorageKey);
  }

  /**
   * 登录
   */
  public authorize() {
    this.resetAuthorizationData();

    if (this._config.Debug) {
      console.log('-----Begin Authorize------');
    }



    var authorizationUrl = this._config.AuthUrl;
    var clientId = this._config.AuthClientId;
    var redirectUri = this._config.AuthCallbackUrl;
    var responseType = 'id_token token';
    var scope = 'openid';
    var nonce = 'N' + Math.random() + '' + Date.now();
    var state = Date.now() + '' + Math.random();

    this.store(this._keys.authStateControl, state);
    this.store(this._keys.authNonce, nonce);


    var url =
      authorizationUrl + '?' +
      'response_type=' + encodeURI(responseType) + '&' +
      'client_id=' + encodeURI(clientId) + '&' +
      'redirect_uri=' + encodeURI(redirectUri) + '&' +
      'scope=' + encodeURI(scope) + '&' +
      'nonce=' + encodeURI(nonce) + '&' +
      'state=' + encodeURI(state);

    window.location.href = url;
  }


  /**
   * 登录callback
   */
  public authorizedCallback() {
    if (this._config.Debug) {
      console.log('------Begin Auth Callback------------');
    }

    this.resetAuthorizationData();

    var hash = window.location.hash.substr(1);
    var result: any = hash.split('&').reduce(function (obj, item) {
      var parts = item.split('=');
      obj[parts[0]] = parts[1];
      return obj;
    }, {});

    if (this._config.Debug) {
      console.log('decoded auth data:', result);
    }

    // begin decode token
    let token = '';
    let idToken = '';
    let isAuthResponseValid = false;

    if (!result.error) {
      if (result.state !== this.retrieve(this._keys.authStateControl)) {
        console.error('AuthorizedCallback incorrect state');
      } else {
        token = result.access_token;
        idToken = result.id_token;

        let jwtHelper = new JwtHelper();
        var jwt = jwtHelper.decodeToken(idToken);

        if (this._config.Debug) {
          console.log('jwt:', jwt);
          console.log('jwt expire time:', jwtHelper.getTokenExpirationDate(idToken));
           //console.log('access_token', jwtHelper.decodeToken(result.access_token));
        }

        if (jwt.nonce !== this.retrieve(this._keys.authNonce)) {
          console.error('AuthorizedCallback incorrect nonce');
        } else {
          this.store(this._keys.authNonce, '');
          this.store(this._keys.authStateControl, '');

          isAuthResponseValid = true;

        }
      }
    }

    if (isAuthResponseValid) {
      this.setAuthenticationData(token, idToken);

      this.router.navigate(['workspaces']);

    } else {
      this.resetAuthorizationData();
      this.router.navigateByUrl('/');
    }
  }

  /**
   * 退出登录
   */
  public Logoff() {
    this.resetAuthorizationData();

    if (this._config.LogoutUrl)
    {
       window.location.href = this._config.LogoutUrl + '?post_logout_redirect_uri=' + encodeURI(this._config.AuthLogoutCallbackUrl) ;
    }
  }


  private resetAuthorizationData() {
    this.storage.removeItem(this._idTokenStorageKey);
    this.storage.removeItem(this._accessTokenStorageKey);
  }

  private setAuthenticationData(token: string, idToken: string) {
    //this.store(this._keys)
    this.store(this._accessTokenStorageKey, token);
    this.store(this._idTokenStorageKey, idToken);
  }

  private retrieve(key: string): any {
    let item = this.storage.getItem(key);

    if (item && item !== 'undefined') {
      return JSON.parse(item);
    }

    return;
  }

  private store(key: string, value: any) {
    this.storage.setItem(key, JSON.stringify(value));
  }
}
