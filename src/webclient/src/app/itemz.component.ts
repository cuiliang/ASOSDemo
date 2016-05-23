import { Component, OnInit, provide } from '@angular/core';
import { Routes , ROUTER_DIRECTIVES, ROUTER_PROVIDERS } from '@angular/router';
import { HTTP_PROVIDERS, Http } from '@angular/http';
import { AUTH_PROVIDERS, AuthConfig, AuthHttp } from 'angular2-jwt';

import { WorkspacesComponent } from './+workspaces';
import { SecurityService } from './shared';
import { AppConfiguration } from './shared';
import { BackendService } from './shared';

@Component({
  moduleId: module.id,
  selector: 'itemz-app',
  templateUrl: 'itemz.component.html',
  styleUrls: ['itemz.component.css'],
  directives: [ROUTER_DIRECTIVES],
  providers: [ROUTER_PROVIDERS,
    HTTP_PROVIDERS,
    AUTH_PROVIDERS,
    provide(AuthHttp, {
      useFactory: (http) => {
        return new AuthHttp(new AuthConfig({
          tokenName:'access_token'
        }), http)
      },
      deps:[Http]
    }),

    SecurityService,
    BackendService,
    AppConfiguration]
})
@Routes([
  {path: '/workspaces', component: WorkspacesComponent}
])
export class ItemzAppComponent  implements OnInit {
  title = 'itemz works!';

  constructor(public securityService: SecurityService) {

  }

  ngOnInit() {
    if (window.location.hash) {
      this.securityService.authorizedCallback();
    }
  }

  public login() {
    this.securityService.authorize();
  }

  public logout() {
    this.securityService.Logoff();
  }
}
