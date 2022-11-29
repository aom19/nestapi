import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
@Injectable()
export class VaultService {
  constructor(private readonly httpService: HttpService) {}

  async getSecrets() {
    const vaultResponse = this.httpService.get(
      'http://host.docker.internal:8200/v1/secret/data/keycloak',
      {
        headers: {
          'X-Vault-Token': 'root',
          'X-Vault-Namespace': 'ns1/ns2/',
        },
      },
    );
    let vaultResponse1 = await firstValueFrom(vaultResponse);
    return vaultResponse1?.data.data.data;
  }
}
