import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto, KeyLoginDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt/dist';
import { HttpService } from '@nestjs/axios';
import jwtDecode, { JwtPayload } from 'jwt-decode';
import { firstValueFrom } from 'rxjs';

type CustomJWtPayload = JwtPayload & {
  sub: string;
  email: string;
  email_verified: boolean;
  resource_access: {
    account: {
      roles: string[];
    };
  };
};

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private httpService: HttpService,
  ) {}

  ///SIGN UP
  async signUpLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);
    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
      },
    });
    const tokens = await this.signTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refreshToken);
    return tokens;
  }

  ///SIGN IN
  async signInLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) {
      throw new ForbiddenException('Access denied');
    }
    const passwordMatch = await bcrypt.compare(dto.password, user.hash);
    if (!passwordMatch) {
      throw new ForbiddenException('Access denied');
    }
    const tokens = await this.signTokens(user.id, user.email);
    return tokens;
  }

  //LOGOUT
  logout(userId: number) {
    return this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  //SIGN IN KEYCLOAK
  async signInKeycloak(dto: KeyLoginDto): Promise<Tokens> {
    // let data1 = {
    //   grant_type: 'password',
    //   client_id: 'nest-app',
    //   client_secret: 'pF1A5HjWMGEihgjiJYPli0XD0sdwBXSD',
    //   username: 'user3',
    //   password: 'admin',
    // };
    let data = {
      username: dto.username,
      password: dto.password,
      grant_type: dto.grant_type,
      client_id: dto.client_id,
      client_secret: dto.client_secret,
    };
    let headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    const j = this.httpService.post(
      'http://host.docker.internal:18080/auth/realms/nest/protocol/openid-connect/token',
      data,
      { headers },
    );
    let a = await firstValueFrom(j);

    console.log('first Value from ');

    const decodedToken = jwtDecode<CustomJWtPayload>(a?.data?.access_token);

    const tokens = await this.signTokens(
      decodedToken?.sub,
      decodedToken?.email,
      decodedToken?.resource_access,
    );
    return tokens;
  }

  //REFRESH TOKEN
  async refreshTokens(userId: number, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.hashedRt) {
      throw new ForbiddenException('Access denied');
    }
    const rtMatch = await bcrypt.compare(rt, user.hashedRt);
    if (!rtMatch) {
      throw new ForbiddenException('Access denied');
    }
    const tokens = await this.signTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refreshToken);
    return tokens;
  }

  //helpers

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }
  async signTokens(
    userId?: number | string,
    email?: string | any,
    roles?: any,
  ): Promise<Tokens> {
    const userRoles = roles?.['nest-app'].roles;
    console.log('userRoles', userRoles);

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, email, userRoles },
        {
          secret: 'at-secret',
          expiresIn: 60 * 15,
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: 'rt-secret',
          expiresIn: 60 * 60 * 24 * 7,
        },
      ),
    ]);

    // const accessToken = await

    return { accessToken, refreshToken };
  }

  async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        hashedRt: hash,
      },
    });
  }
  getHello(): string {
    return 'Hello';
  }
  getAdmin(): string {
    return 'Admin';
  }
}
