import { HttpModule, HttpService } from '@nestjs/axios';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { KeycloakService } from './keycloak.service';
import { RtStrategy, AtStrategy } from './strategies';
import { VaultService } from './vault.service';

@Module({
  imports: [JwtModule.register({}), HttpModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    AtStrategy,
    RtStrategy,
    VaultService,
    KeycloakService,
  ],
})
export class AuthModule {}
