import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit,OnModuleDestroy {
    findOne(arg0: { where: { id: number; }; }) {
      throw new Error('Method not implemented.');
    }
    update(arg0: { hashed_refresh_token: string; }, arg1: { where: { id: any; }; returning: boolean; }) {
      throw new Error('Method not implemented.');
    }
    constructor(){super({
        datasources:{
            db:{
                // url:"postgresql://fotimac:2020@localhost:5432/prisma-passport?schema=public"
                url:process.env.DATABASE_URL
            }
        }
    })
    
    }


    async onModuleInit() {
    await this.$connect();
    }
    async onModuleDestroy() {
    await this.$disconnect();
    }
}
