import { Injectable } from '@angular/core';
import { AuthHttp } from 'angular2-jwt';
import { Http } from '@angular/http';
import { Observable } from 'rxjs/Observable';

@Injectable()
export class BackendService {

  constructor(private http: AuthHttp) {

  }

  public getDate (): Observable<any> {
    return this.http.get('http://localhost:8000/api/Test/getuserinfo');
  }
}
