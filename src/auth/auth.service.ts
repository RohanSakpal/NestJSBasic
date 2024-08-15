import { ForbiddenException, Injectable } from "@nestjs/common";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaService } from "src/prisma/prisma.service";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt:JwtService,
        private config:ConfigService
    ) {}

    async signup(dto:AuthDto) {
        //generate password hash
        const hash = await argon.hash(dto.password);

        //save the new user
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
                //only show this field
                // select: {
                //     id:true,
                //     email:true,
                //     createdAt: true
                // }
            });
    
            return this.signToken(user.id, user.email);
        } catch(error) {
            if(error instanceof PrismaClientKnownRequestError) {
                if(error.code === 'P2002') {
                    throw new ForbiddenException('Credentials taken');
                }
            }
        }
    }

    async signin(dto:AuthDto) {
        //find user from email
        const user = await this.prisma.user.findFirst({
            where: {
                email: dto.email,
            },
        })
        //if user does not exist throw exception
        if(!user)
            throw new ForbiddenException(
                'Credentials incorrect'
            );
        //compare password
        const pwMatches = await argon.verify(
            user.hash,
            dto.password,
        );

        //if password incorrect throw exception
        if(!pwMatches) {
            throw new ForbiddenException(
                'Credentials incorrect'
            )
        }
        //send back the user token
        return this.signToken(user.id, user.email);
    }

    async signToken(userId: number,email: string): Promise<{access_token}> {
        const payload = {
            sub: userId,
            email
        };

        const secret = this.config.get('JWT_SECRET');
        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: secret
        });

        return {
            access_token: token,
        }
    }
}