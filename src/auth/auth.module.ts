import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import {JwtModule} from '@nestjs/jwt'
import { AccessTokenStrategy } from '../common/strategies';

@Module({
  imports:[JwtModule.register({}) ,PrismaModule],
  controllers: [AuthController],
  providers: [AuthService,
  AccessTokenStrategy
  ],
})
export class AuthModule {}
