import { Injectable, Inject } from '@nestjs/common';
import { Redis } from 'ioredis';
import { REDIS_CLIENT } from '../../redis/redis.module';

@Injectable()
export class SessionService {
  constructor(@Inject(REDIS_CLIENT) private readonly redis: Redis) {}

  /**
   * Armazena os dados da sessão de um usuário
   * @param userId ID do usuário
   * @param sessionId ID da sessão
   * @param data Dados da sessão
   * @param ttl Tempo de vida em segundos (padrão: 7 dias)
   */
  async storeSession(
    userId: string,
    sessionId: string,
    data: Record<string, any>,
    ttl = 60 * 60 * 24 * 7,
  ): Promise<void> {
    const key = `session:${userId}:${sessionId}`;
    await this.redis.set(key, JSON.stringify(data), 'EX', ttl);
  }

  /**
   * Recupera os dados de uma sessão
   * @param userId ID do usuário
   * @param sessionId ID da sessão
   * @returns Dados da sessão ou null se não existir
   */
  async getSession(userId: string, sessionId: string): Promise<Record<string, any> | null> {
    const key = `session:${userId}:${sessionId}`;
    const data = await this.redis.get(key);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Remove uma sessão específica
   * @param userId ID do usuário
   * @param sessionId ID da sessão
   */
  async removeSession(userId: string, sessionId: string): Promise<void> {
    const key = `session:${userId}:${sessionId}`;
    await this.redis.del(key);
  }

  /**
   * Remove todas as sessões de um usuário
   * @param userId ID do usuário
   */
  async removeAllUserSessions(userId: string): Promise<void> {
    const keys = await this.redis.keys(`session:${userId}:*`);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }

  /**
   * Lista todas as sessões ativas de um usuário
   * @param userId ID do usuário
   * @returns Array de IDs de sessão
   */
  async listUserSessions(userId: string): Promise<string[]> {
    const keys = await this.redis.keys(`session:${userId}:*`);
    return keys.map(key => key.split(':')[2]);
  }
} 