import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Get,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';

import { AuthDto, KeyLoginDto } from './dto';
import { Tokens } from './types';
import {} from '@nestjs/passport';

import { RtGuard, AtGuard, AdminGuard } from './common/guards';
import { GetCurrentUser, GetCurrentUserId, Public } from './common/decorators';
import { HttpService } from '@nestjs/axios';
import { PermissionGuard } from './common/guards/permission.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signUpLocal(dto);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signInLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signInLocal(dto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUserId() userId: number) {
    return this.authService.logout(userId);
  }

  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') rt: string,
  ) {
    return this.authService.refreshTokens(userId, rt);
  }

  @Public()
  @Post('keycloak')
  @HttpCode(HttpStatus.OK)
  signInKeycloak(@Body() dto: KeyLoginDto): Promise<Tokens> {
    return this.authService.signInKeycloak(dto);
  }

  @Public()
  @Get('/public')
  getpublic(): string {
    return `${this.authService.getHello()} from public`;
  }

  // @UseGuards(AtGuard)
  @UseGuards(PermissionGuard('admin'))
  @Get('/admin')
  getAdmin(): string {
    return `${this.authService.getHello()} from auth admin`;
  }

  @UseGuards(PermissionGuard('user'))
  @Get('/user')
  getUser(): string {
    return `${this.authService.getHello()} from auth user`;
  }
}
