import { Injectable, Inject } from '@nestjs/common';
import { Redis } from 'ioredis';
import { REDIS_CLIENT } from '../../redis/redis.module';
import { v4 as uuidv4 } from 'uuid';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class TokenService {
  constructor(
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Gera um token único para redefinição de senha
   * @param userId ID do usuário
   * @returns Token gerado
   */
  async generatePasswordResetToken(userId: string): Promise<string> {
    const token = uuidv4();
    const key = `password_reset:${token}`;
    
    // Armazena o token no Redis com validade de 1 hora
    const ttl: number = this.configService.get<number>("PASSWORD_RESET_TTL") || 3600;
    await this.redis.set(key, userId, 'EX', ttl);
    
    return token;
  }

  /**
   * Verifica e valida um token de redefinição de senha
   * @param token Token de redefinição
   * @returns ID do usuário associado ao token, ou null se inválido
   */
  async verifyPasswordResetToken(token: string): Promise<string | null> {
    const key = `password_reset:${token}`;
    const userId = await this.redis.get(key);
    
    return userId;
  }

  /**
   * Invalida um token de redefinição de senha após o uso
   * @param token Token a ser invalidado
   */
  async invalidatePasswordResetToken(token: string): Promise<void> {
    const key = `password_reset:${token}`;
    await this.redis.del(key);
  }

  /**
   * Gera um token para verificação de email
   * @param userId ID do usuário
   * @returns Token gerado
   */
  async generateEmailVerificationToken(userId: string): Promise<string> {
    const token = uuidv4();
    const key = `email_verification:${token}`;
    
    // Armazena o token no Redis com validade de 24 horas
    const ttl: number = this.configService.get<number>("EMAIL_VERIFICATION_TTL") || 86400;
    await this.redis.set(key, userId, 'EX', ttl);
    
    return token;
  }

  /**
   * Verifica e valida um token de verificação de email
   * @param token Token de verificação
   * @returns ID do usuário associado ao token, ou null se inválido
   */
  async verifyEmailVerificationToken(token: string): Promise<string | null> {
    const key = `email_verification:${token}`;
    const userId = await this.redis.get(key);
    
    return userId;
  }

  /**
   * Invalida um token de verificação de email após o uso
   * @param token Token a ser invalidado
   */
  async invalidateEmailVerificationToken(token: string): Promise<void> {
    const key = `email_verification:${token}`;
    await this.redis.del(key);
  }
} 