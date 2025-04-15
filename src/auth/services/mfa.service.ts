import { Injectable, Inject } from '@nestjs/common';
import { authenticator } from 'otplib';
import { toDataURL } from 'qrcode';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { Redis } from 'ioredis';
import { REDIS_CLIENT } from '../../redis/redis.module';
import { ConfigService } from '@nestjs/config';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class MfaService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @Inject(REDIS_CLIENT)
    private readonly redis: Redis,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Gera um segredo MFA para um usuário
   * @param userId ID do usuário
   * @returns Objeto com o segredo e QR code
   */
  async generateMfaSecret(userId: string) {
    // Buscar usuário
    const user = await this.userRepository.findOneBy({ id: userId });
    if (!user) {
      throw new Error('Usuário não encontrado');
    }

    // Gerar segredo
    const secret = authenticator.generateSecret();
    
    // Definir nome da aplicação para o QR code
    const appName = this.configService.get<string>('APP_NAME') || 'Visa Platform';
    
    // Criar URI do TOTP para o QR code
    const otpauth = authenticator.keyuri(user.email, appName, secret);
    
    // Gerar QR code como Data URL
    const qrCodeUrl = await toDataURL(otpauth);
    
    // Armazenar segredo temporariamente no Redis
    // Quando o usuário verificar, então salvaremos no banco de dados
    const tempId = uuidv4();
    await this.redis.set(`mfa_setup:${userId}:${tempId}`, secret, 'EX', 600); // 10 minutos
    
    return {
      tempId,
      secret,
      qrCodeUrl,
    };
  }

  /**
   * Verifica se um token TOTP é válido
   * @param token Token TOTP
   * @param secret Segredo TOTP
   * @returns Booleano indicando se o token é válido
   */
  verifyToken(token: string, secret: string): boolean {
    try {
      return authenticator.verify({ token, secret });
    } catch (error) {
      return false;
    }
  }

  /**
   * Ativa o MFA para um usuário após verificação bem-sucedida
   * @param userId ID do usuário
   * @param tempId ID temporário
   * @param token Token TOTP para verificação
   * @returns Booleano indicando sucesso
   */
  async activateMfa(userId: string, tempId: string, token: string): Promise<boolean> {
    // Buscar o segredo temporário
    const key = `mfa_setup:${userId}:${tempId}`;
    const secret = await this.redis.get(key);
    
    if (!secret) {
      throw new Error('Configuração MFA expirada ou inválida');
    }
    
    // Verificar o token
    const isValid = this.verifyToken(token, secret);
    
    if (!isValid) {
      return false;
    }
    
    // Buscar usuário
    const user = await this.userRepository.findOneBy({ id: userId });
    if (!user) {
      throw new Error('Usuário não encontrado');
    }
    
    // Ativar MFA para o usuário
    user.mfaEnabled = true;
    user.mfaSecret = secret;
    await this.userRepository.save(user);
    
    // Remover configuração temporária
    await this.redis.del(key);
    
    return true;
  }

  /**
   * Desativa o MFA para um usuário
   * @param userId ID do usuário
   */
  async deactivateMfa(userId: string): Promise<boolean> {
    // Buscar usuário
    const user = await this.userRepository.findOneBy({ id: userId });
    if (!user) {
      throw new Error('Usuário não encontrado');
    }
    
    if (!user.mfaEnabled) {
      return false; // Já está desativado
    }
    
    // Desativar MFA
    user.mfaEnabled = false;
    user.mfaSecret = null;
    await this.userRepository.save(user);
    
    return true;
  }

  /**
   * Cria uma sessão de verificação MFA temporária durante o login
   * @param userId ID do usuário
   * @returns ID da sessão criada
   */
  async createMfaSession(userId: string): Promise<string> {
    const sessionId = uuidv4();
    const key = `mfa_session:${sessionId}`;
    
    // Armazenar ID do usuário na sessão MFA temporária
    // Válido por 5 minutos
    await this.redis.set(key, userId, 'EX', 300);
    
    return sessionId;
  }

  /**
   * Verifica e valida uma sessão MFA
   * @param sessionId ID da sessão temporária
   * @param token Token TOTP fornecido pelo usuário
   * @returns ID do usuário ou null se inválido
   */
  async verifyMfaSession(sessionId: string, token: string): Promise<string | null> {
    const key = `mfa_session:${sessionId}`;
    const userId = await this.redis.get(key);
    
    if (!userId) {
      return null; // Sessão inválida ou expirada
    }
    
    // Buscar usuário
    const user = await this.userRepository.findOneBy({ id: userId });
    if (!user || !user.mfaEnabled || !user.mfaSecret) {
      return null;
    }
    
    // Verificar token
    const isValid = this.verifyToken(token, user.mfaSecret);
    
    if (!isValid) {
      return null;
    }
    
    // Limpar sessão
    await this.redis.del(key);
    
    return userId;
  }

  /**
   * Gera códigos de backup para um usuário
   * @param userId ID do usuário
   * @returns Array de códigos de backup
   */
  async generateBackupCodes(userId: string): Promise<string[]> {
    // Gerar 8 códigos de backup de 8 caracteres
    const backupCodes = Array.from({ length: 8 }, () => {
      // Gerar código aleatório de 8 caracteres (letras e números)
      return Math.random().toString(36).substring(2, 10).toUpperCase();
    });
    
    // Armazenar códigos com hash
    const hashedCodes = backupCodes.map(code => {
      // Na implementação real, devemos usar um hash como bcrypt 
      // Aqui simplificamos por agora
      return code;
    });
    
    // Salvar no Redis (na implementação real, salvaríamos no banco de dados)
    // Usamos Redis para simplificar o exemplo
    await this.redis.set(`mfa_backup:${userId}`, JSON.stringify(hashedCodes), 'EX', 86400 * 365); // 1 ano
    
    return backupCodes;
  }

  /**
   * Verifica um código de backup
   * @param userId ID do usuário
   * @param code Código de backup fornecido
   * @returns Booleano indicando se o código é válido
   */
  async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const storedCodesJson = await this.redis.get(`mfa_backup:${userId}`);
    
    if (!storedCodesJson) {
      return false;
    }
    
    const storedCodes = JSON.parse(storedCodesJson);
    
    // Verifica se o código está na lista
    // Na implementação real, verificaríamos o hash
    const isValid = storedCodes.includes(code);
    
    if (isValid) {
      // Remove o código usado
      const updatedCodes = storedCodes.filter(c => c !== code);
      await this.redis.set(`mfa_backup:${userId}`, JSON.stringify(updatedCodes), 'EX', 86400 * 365);
    }
    
    return isValid;
  }
} 