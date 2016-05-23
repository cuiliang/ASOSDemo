import { Component, OnInit } from '@angular/core';

import { BackendService }  from '../shared'

@Component({
  moduleId: module.id,
  selector: 'app-workspaces',
  templateUrl: 'workspaces.component.html',
  styleUrls: ['workspaces.component.css']
})
export class WorkspacesComponent implements OnInit {

  constructor(private backend: BackendService) {}

  ngOnInit() {
  }

  getDate (): any{
      this.backend.getDate()
        .subscribe( data => {
          console.log('returned data:', data);
        } ,
        err => console.log('err:', err),
        () => console.log('Request Complete')
        )
  }
}
