import { Controller, Post, Body, HttpCode, HttpStatus, BadRequestException, Get, Req, UseGuards, Res, UnauthorizedException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AuthService } from './services/auth.service';
import { EmailService } from '../email/email.service';
import { TokenService } from './services/token.service';
import { MfaService } from './services/mfa.service';
import { ConfigService } from '@nestjs/config';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { SetupMfaDto } from './dto/setup-mfa.dto';
import { VerifyMfaDto } from './dto/verify-mfa.dto';
import { VerifyBackupCodeDto } from './dto/verify-backup-code.dto';
import { GenerateMfaResponseDto } from './dto/generate-mfa.dto';
import { BackupCodesResponseDto } from './dto/backup-codes.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../users/entities/user.entity';
import { PasswordUtils } from './utils/password.util';
import { AuthGuard } from '@nestjs/passport';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly mfaService: MfaService,
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

  // Autenticação com Google
  @Get('google')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Iniciar autenticação com Google' })
  googleAuth() {
    // Este endpoint inicia o processo de autenticação
    // A lógica é tratada pelo guard do Passport
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({ summary: 'Callback da autenticação Google' })
  @ApiResponse({ status: 200, description: 'Autenticação com Google bem sucedida' })
  @ApiResponse({ status: 400, description: 'Erro na autenticação' })
  async googleAuthCallback(@Req() req, @Res() res) {
    const user = req.user;
    const authResult = await this.authService.login(user);
    
    // Verificar se MFA é necessário
    if (authResult.requireMfa) {
      // Redirecionar para a página de verificação MFA
      const frontendUrl = this.configService.get('FRONTEND_URL');
      const redirectUrl = `${frontendUrl}/auth/mfa?sessionId=${authResult.sessionId}`;
      return res.redirect(redirectUrl);
    }
    
    // Redirecionar para a aplicação frontend com o token
    const frontendUrl = this.configService.get('FRONTEND_URL');
    const redirectUrl = `${frontendUrl}/auth/oauth-callback?access_token=${authResult.accessToken}&refresh_token=${authResult.refreshToken}`;
    
    return res.redirect(redirectUrl);
  }

  // Autenticação com LinkedIn
  @Get('linkedin')
  @UseGuards(AuthGuard('linkedin'))
  @ApiOperation({ summary: 'Iniciar autenticação com LinkedIn' })
  linkedinAuth() {
    // Este endpoint inicia o processo de autenticação
    // A lógica é tratada pelo guard do Passport
  }

  @Get('linkedin/callback')
  @UseGuards(AuthGuard('linkedin'))
  @ApiOperation({ summary: 'Callback da autenticação LinkedIn' })
  @ApiResponse({ status: 200, description: 'Autenticação com LinkedIn bem sucedida' })
  @ApiResponse({ status: 400, description: 'Erro na autenticação' })
  async linkedinAuthCallback(@Req() req, @Res() res) {
    const user = req.user;
    const authResult = await this.authService.login(user);
    
    // Verificar se MFA é necessário
    if (authResult.requireMfa) {
      // Redirecionar para a página de verificação MFA
      const frontendUrl = this.configService.get('FRONTEND_URL');
      const redirectUrl = `${frontendUrl}/auth/mfa?sessionId=${authResult.sessionId}`;
      return res.redirect(redirectUrl);
    }
    
    // Redirecionar para a aplicação frontend com o token
    const frontendUrl = this.configService.get('FRONTEND_URL');
    const redirectUrl = `${frontendUrl}/auth/oauth-callback?access_token=${authResult.accessToken}&refresh_token=${authResult.refreshToken}`;
    
    return res.redirect(redirectUrl);
  }

  // ======== Endpoints MFA ========
  
  @Post('mfa/generate')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Gerar configuração inicial de MFA' })
  @ApiResponse({ status: 200, description: 'Configuração MFA gerada com sucesso', type: GenerateMfaResponseDto })
  @ApiResponse({ status: 401, description: 'Não autorizado' })
  async generateMfa(@Req() req): Promise<GenerateMfaResponseDto> {
    const userId = req.user.sub;
    
    try {
      return await this.mfaService.generateMfaSecret(userId);
    } catch (error) {
      throw new BadRequestException('Não foi possível gerar a configuração MFA');
    }
  }

  @Post('mfa/verify')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verificar e ativar MFA' })
  @ApiResponse({ status: 200, description: 'MFA ativado com sucesso' })
  @ApiResponse({ status: 400, description: 'Token inválido' })
  @ApiResponse({ status: 401, description: 'Não autorizado' })
  async verifyMfa(@Req() req, @Body() dto: SetupMfaDto) {
    const userId = req.user.sub;
    const { token } = dto;
    
    // Buscar o usuário para verificar se já tem MFA ativado
    const user = await this.userRepository.findOne({ where: { id: userId } });
    
    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado');
    }
    
    if (user.mfaEnabled) {
      throw new BadRequestException('MFA já está ativado para este usuário');
    }
    
    // Verificar o tempId e token
    // O tempId deve estar nos headers como X-MFA-TEMP-ID
    const tempId = req.headers['x-mfa-temp-id'];
    
    if (!tempId) {
      throw new BadRequestException('ID temporário ausente');
    }
    
    // Verificar e ativar MFA
    const success = await this.mfaService.activateMfa(userId, tempId, token);
    
    if (!success) {
      throw new BadRequestException('Token MFA inválido');
    }
    
    // Gerar códigos de backup
    const backupCodes = await this.mfaService.generateBackupCodes(userId);
    
    return { 
      message: 'MFA ativado com sucesso',
      backupCodes 
    };
  }

  @Post('mfa/disable')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Desativar MFA' })
  @ApiResponse({ status: 200, description: 'MFA desativado com sucesso' })
  @ApiResponse({ status: 400, description: 'MFA não está ativado' })
  @ApiResponse({ status: 401, description: 'Não autorizado' })
  async disableMfa(@Req() req) {
    const userId = req.user.sub;
    
    const success = await this.mfaService.deactivateMfa(userId);
    
    if (!success) {
      throw new BadRequestException('MFA não está ativado para este usuário');
    }
    
    return { message: 'MFA desativado com sucesso' };
  }

  @Post('mfa/validate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Validar token MFA durante login' })
  @ApiResponse({ status: 200, description: 'Token MFA válido' })
  @ApiResponse({ status: 401, description: 'Token MFA inválido' })
  async validateMfa(@Body() dto: VerifyMfaDto) {
    const { token, sessionId } = dto;
    
    // Verificar o token MFA
    const userId = await this.mfaService.verifyMfaSession(sessionId, token);
    
    if (!userId) {
      throw new UnauthorizedException('Token MFA inválido ou sessão expirada');
    }
    
    // Completar o login com MFA
    return this.authService.completeMfaLogin(sessionId);
  }

  @Post('mfa/backup-code')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Validar código de backup durante login' })
  @ApiResponse({ status: 200, description: 'Código de backup válido' })
  @ApiResponse({ status: 401, description: 'Código de backup inválido' })
  async validateBackupCode(@Body() dto: VerifyBackupCodeDto) {
    const { code, sessionId } = dto;
    
    // Obter o ID do usuário associado à sessão
    const userId = await this.authService.checkMfaPendingSession(sessionId);
    
    if (!userId) {
      throw new UnauthorizedException('Sessão inválida ou expirada');
    }
    
    // Verificar o código de backup
    const isValid = await this.mfaService.verifyBackupCode(userId, code);
    
    if (!isValid) {
      throw new UnauthorizedException('Código de backup inválido');
    }
    
    // Completar o login com o código de backup
    return this.authService.completeMfaLogin(sessionId);
  }

  @Get('mfa/backup-codes')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Gerar novos códigos de backup para MFA' })
  @ApiResponse({ status: 200, description: 'Códigos de backup gerados com sucesso', type: BackupCodesResponseDto })
  @ApiResponse({ status: 401, description: 'Não autorizado' })
  async generateBackupCodes(@Req() req): Promise<BackupCodesResponseDto> {
    const userId = req.user.sub;
    
    // Verificar se o usuário tem MFA ativado
    const user = await this.userRepository.findOne({ where: { id: userId } });
    
    if (!user || !user.mfaEnabled) {
      throw new BadRequestException('MFA não está ativado para este usuário');
    }
    
    // Gerar novos códigos de backup
    const backupCodes = await this.mfaService.generateBackupCodes(userId);
    
    return { backupCodes };
  }
} 