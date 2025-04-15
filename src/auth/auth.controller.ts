import { Controller, Post, Body, HttpCode, HttpStatus, BadRequestException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AuthService } from './services/auth.service';
import { EmailService } from '../email/email.service';
import { TokenService } from './services/token.service';
import { ConfigService } from '@nestjs/config';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../users/entities/user.entity';
import { PasswordUtils } from './utils/password.util';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly configService: ConfigService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  @Post('request-password-reset')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Solicitar redefinição de senha' })
  @ApiResponse({ status: 200, description: 'Email de redefinição enviado com sucesso' })
  @ApiResponse({ status: 400, description: 'Email inválido ou não encontrado' })
  async requestPasswordReset(@Body() dto: RequestPasswordResetDto) {
    const { email } = dto;
    
    // Verificar se o usuário existe
    const user = await this.userRepository.findOne({ where: { email } });
    
    if (!user) {
      // Não informamos se o email existe ou não por segurança
      return { message: 'Se o email estiver registrado, você receberá um link para redefinição de senha' };
    }
    
    // Gerar token de redefinição
    const token = await this.tokenService.generatePasswordResetToken(user.id);
    
    // Gerar link de redefinição
    const resetLink = `${this.configService.get('FRONTEND_URL')}/reset-password?token=${token}`;
    
    // Enviar email
    try {
      await this.emailService.sendPasswordResetEmail(email, resetLink);
      return { message: 'Se o email estiver registrado, você receberá um link para redefinição de senha' };
    } catch (error) {
      throw new BadRequestException('Não foi possível enviar o email de redefinição. Tente novamente mais tarde.');
    }
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Redefinir senha com token' })
  @ApiResponse({ status: 200, description: 'Senha redefinida com sucesso' })
  @ApiResponse({ status: 400, description: 'Token inválido ou expirado' })
  async resetPassword(@Body() dto: ResetPasswordDto) {
    const { token, password, confirmPassword } = dto;
    
    // Verificar se as senhas coincidem
    if (password !== confirmPassword) {
      throw new BadRequestException('As senhas não coincidem');
    }
    
    // Verificar se o token é válido
    const userId = await this.tokenService.verifyPasswordResetToken(token);
    
    if (!userId) {
      throw new BadRequestException('Token inválido ou expirado');
    }
    
    // Buscar o usuário
    const user = await this.userRepository.findOne({ where: { id: userId } });
    
    if (!user) {
      throw new BadRequestException('Usuário não encontrado');
    }
    
    // Atualizar a senha
    user.password = await PasswordUtils.hash(password);
    await this.userRepository.save(user);
    
    // Invalidar o token
    await this.tokenService.invalidatePasswordResetToken(token);
    
    // Invalidar todas as sessões ativas do usuário
    await this.authService.invalidateAllSessions(userId);
    
    return { message: 'Senha redefinida com sucesso' };
  }
} 