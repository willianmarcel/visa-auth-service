import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { PasswordUtils } from '../utils/password.util';
import { SessionService } from './session.service';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly sessionService: SessionService,
  ) {}

  /**
   * Valida as credenciais de um usuário
   * @param email Email do usuário
   * @param password Senha do usuário
   * @returns Usuário se autenticado, ou null
   */
  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      return null;
    }

    const isPasswordValid = await PasswordUtils.validate(password, user.password);

    if (!isPasswordValid) {
      return null;
    }

    return user;
  }

  /**
   * Realiza o login do usuário e gera um token JWT
   * @param user Usuário autenticado
   * @returns Token de acesso e informações de refresh ou necessidade de MFA
   */
  async login(user: User) {
    // Verifica se o usuário tem MFA ativado
    if (user.mfaEnabled) {
      // Cria uma sessão temporária para o fluxo de MFA
      // Esta sessão será usada para validar o token MFA
      const sessionId = uuidv4();
      const key = `mfa_pending:${sessionId}`;
      
      // Armazena o ID do usuário na sessão temporária (válida por 5 minutos)
      await this.sessionService.storeValue(key, user.id, 300);
      
      // Retorna informação de que MFA é necessário
      return {
        requireMfa: true,
        sessionId,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
        },
      };
    }
    
    // Se não tem MFA, segue o fluxo normal de login
    return this.generateTokens(user);
  }

  /**
   * Gera tokens de acesso e refresh para o usuário
   * @param user Usuário autenticado
   * @returns Tokens de acesso e refresh
   */
  async generateTokens(user: User) {
    const payload = { 
      sub: user.id, 
      email: user.email,
      roles: user.roles 
    };
    
    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_SECRET'),
      expiresIn: '15m',
    });
    
    const refreshToken = uuidv4();
    
    // Armazena o token de refresh no Redis
    await this.sessionService.storeSession(
      user.id,
      refreshToken,
      { ...payload, tokenId: refreshToken },
      60 * 60 * 24 * 30, // 30 dias
    );
    
    return {
      accessToken,
      refreshToken,
      expiresIn: 900, // 15 minutos em segundos
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        roles: user.roles,
      },
    };
  }

  /**
   * Verifica uma sessão MFA pendente
   * @param sessionId ID da sessão temporária
   * @returns ID do usuário associado à sessão ou null
   */
  async checkMfaPendingSession(sessionId: string): Promise<string | null> {
    const key = `mfa_pending:${sessionId}`;
    return this.sessionService.getValue(key);
  }

  /**
   * Completa o login após verificação MFA
   * @param sessionId ID da sessão temporária
   * @returns Tokens de acesso e refresh ou erro
   */
  async completeMfaLogin(sessionId: string): Promise<any> {
    const key = `mfa_pending:${sessionId}`;
    const userId = await this.sessionService.getValue(key);
    
    if (!userId) {
      throw new UnauthorizedException('Sessão MFA inválida ou expirada');
    }
    
    // Busca o usuário
    const user = await this.userRepository.findOneBy({ id: userId });
    
    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado');
    }
    
    // Remove a sessão temporária
    await this.sessionService.removeValue(key);
    
    // Gera os tokens
    return this.generateTokens(user);
  }

  /**
   * Atualiza o token de acesso usando um token de refresh
   * @param userId ID do usuário
   * @param refreshToken Token de refresh
   * @returns Novo token de acesso
   */
  async refreshToken(userId: string, refreshToken: string) {
    const session = await this.sessionService.getSession(userId, refreshToken);
    
    if (!session) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    
    const user = await this.userRepository.findOneBy({ id: userId });
    
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    
    // Gera um novo token de acesso
    return this.generateTokens(user);
  }

  /**
   * Realiza o logout do usuário
   * @param userId ID do usuário
   * @param refreshToken Token de refresh
   */
  async logout(userId: string, refreshToken: string): Promise<void> {
    await this.sessionService.removeSession(userId, refreshToken);
  }

  /**
   * Invalida todas as sessões de um usuário
   * @param userId ID do usuário
   */
  async invalidateAllSessions(userId: string): Promise<void> {
    await this.sessionService.removeAllUserSessions(userId);
  }

  /**
   * Encontra ou cria um usuário baseado nas informações de OAuth
   * @param userData Dados do usuário do provedor OAuth
   * @param provider Provedor OAuth (google, linkedin)
   * @returns Usuário encontrado ou criado
   */
  async findOrCreateOAuthUser(
    userData: {
      email: string;
      firstName: string;
      lastName: string;
      googleId?: string;
      linkedinId?: string;
      profilePicture?: string;
    },
    provider: 'google' | 'linkedin',
  ): Promise<User> {
    // Determina o tipo de ID baseado no provedor
    const providerIdField = provider === 'google' ? 'googleId' : 'linkedinId';
    const providerId = provider === 'google' ? userData.googleId : userData.linkedinId;

    // Tenta encontrar o usuário pelo ID do provedor OAuth
    let user = await this.userRepository.findOne({
      where: { [providerIdField]: providerId },
    });

    // Se não encontrou pelo ID do provedor, tenta pelo email
    if (!user && userData.email) {
      user = await this.userRepository.findOne({
        where: { email: userData.email },
      });

      // Se encontrou pelo email, atualiza com o ID do provedor
      if (user) {
        user[providerIdField] = providerId;
        await this.userRepository.save(user);
      }
    }

    // Se não encontrou por nenhum método, cria um novo usuário
    if (!user) {
      const randomPassword = uuidv4(); // Gera uma senha aleatória
      const hashedPassword = await PasswordUtils.hash(randomPassword);

      user = this.userRepository.create({
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName,
        password: hashedPassword,
        [providerIdField]: providerId,
        profilePicture: userData.profilePicture,
        emailVerified: true, // Como veio do OAuth, consideramos o email verificado
        roles: ['user'], // Papel padrão para novos usuários
      });

      await this.userRepository.save(user);
    }

    return user;
  }
} 