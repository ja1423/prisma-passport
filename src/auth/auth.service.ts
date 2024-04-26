import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { CreateAuthDto,UpdateAuthDto } from './dto';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Response } from 'express';
import { JwtPayload, Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };
    console.log(4);

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async updateRefreshToken(userId: number, refreshToken: string) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 7);
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRefreshToken,
      },
    });
  }

  async signUp(createAuthDto: CreateAuthDto, res: Response): Promise<Tokens> {
    const candidate = await this.prismaService.user.findUnique({
      where: {
        email: createAuthDto.email,
      },
    });

    if (candidate) {
      throw new BadRequestException('User already exists');
    }

    const hashedPassword = await bcrypt.hash(createAuthDto.password, 7);

    const newUser = await this.prismaService.user.create({
      data: {
        name: createAuthDto.name,
        email: createAuthDto.email,
        hashedPassword,
      },
    });
    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRefreshToken(newUser.id, tokens.refresh_token);

    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });
    return tokens;
  }

  async signIn(
    email: string,
    password: string,
    res: Response,
  ): Promise<Tokens> {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: email ,
      },
    });

    if (!user) {
      throw new BadRequestException('Invalid email or password');
    }

    const passwordMatch = await bcrypt.compare(password, user.hashedPassword);

    if (!passwordMatch) {
      throw new BadRequestException('Invalid email or password');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });

    return tokens;
  }

async signout(refreshToken:string,res:Response){
    const userData=await this.jwtService.verify(refreshToken,{
      secret:process.env.REFRESH_TOKEN_KEY,
    });
    if(!userData){
      throw new ForbiddenException('Refresh token is invalid');
    }
    const updateUser=await this.prismaService.update({
      hashed_refresh_token:null,
    },
    {
      where:{id:userData.id},
      returning:true,
    })
    res.clearCookie('refresh_token');
    const response={
      message:"user logout successfully",
      user_refresh_token:updateUser[1][0].hashed_refresh_token
    }
    }
 
  async refreshToken(userId:number,refreshToken:string,res:Response){
        const decodedToken=await this.jwtService.decode(refreshToken)
        if(userId!==decodedToken['id']){
          throw new BadRequestException('Refresh token is invalid');
        }

        const user=await this.prismaService.findOne({where:{id:userId}});

        if(!user||!user.hashedRefreshToken){
          throw new BadRequestException('user does not exist');
        }

        const tokenMatch=await bcrypt.compare(
          refreshToken,
          user.hashed_refresh_token
        );

        if(!tokenMatch){
          throw new ForbiddenException('Forbidden');
        }

      const tokens = await this.getTokens(user.id,user.email);
      const hashed_refresh_token = await bcrypt.hash(tokens.refresh_token, 7);
      const updatedUser = await this.prismaService.update(
        { hashed_refresh_token },
        {
          where: { id: user.id },
          returning: true,
        },
      );
      res.cookie('refresh_token', tokens.refresh_token, {
        maxAge: 15 * 24 * 60 * 60 * 1000,
        httpOnly: true,
      });
      const response = {
        message: 'User logged in',
        user: updatedUser[1][0],
        tokens,
      };
      return response;
      }

  create(createAuthDto: CreateAuthDto) {
    return 'This action adds a new auth';
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
