import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

type keycloakReq = {
  grant_type: string;
  client_id: string;
  client_secret: string;
  username: string;
  password: string;
};

@Injectable()
export class KeycloakService {
  constructor(private readonly httpService: HttpService) {}

  async keycloakLogin(data: keycloakReq) {
    let headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };
    const j = this.httpService.post(
      'http://host.docker.internal:18080/auth/realms/nest/protocol/openid-connect/token',
      data,
      { headers },
    );
    let a = await firstValueFrom(j);
    return a.data;
  }
}
