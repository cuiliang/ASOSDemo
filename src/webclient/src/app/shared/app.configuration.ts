import {Injectable} from '@angular/core';

/* tslint:disable */

/**
 * 应用程序配置
 */
@Injectable()
export class AppConfiguration {
    public AuthUrl: string = 'http://localhost:8000/connect/authorize';
    public LogoutUrl: string = 'http://localhost:8000/connect/logout';
    public AuthCallbackUrl: string = 'http://localhost:4200';
    public AuthLogoutCallbackUrl: string = 'http://localhost:4200';
    public AuthClientId: string = 'itemzWeb';

    public Debug: boolean = true;
}
