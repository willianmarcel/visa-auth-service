import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor(private readonly configService: ConfigService) {
    this.initializeTransporter();
  }

  private initializeTransporter() {
    const host = this.configService.get<string>('EMAIL_HOST');
    const port = this.configService.get<number>('EMAIL_PORT');
    const user = this.configService.get<string>('EMAIL_USER');
    const pass = this.configService.get<string>('EMAIL_PASSWORD');
    const secure = this.configService.get<boolean>('EMAIL_SECURE') || false;

    try {
      this.transporter = nodemailer.createTransport({
        host,
        port,
        secure,
        auth: {
          user,
          pass,
        },
      });
      this.logger.log('Email transporter initialized successfully');
    } catch (error) {
      this.logger.error(`Failed to initialize email transporter: ${error.message}`);
      throw error;
    }
  }

  /**
   * Envia um email
   * @param to Destinatário
   * @param subject Assunto
   * @param html Conteúdo HTML
   * @returns Informações de envio
   */
  async sendEmail(to: string, subject: string, html: string): Promise<any> {
    const from = this.configService.get<string>('EMAIL_FROM') || 'noreply@example.com';

    try {
      const info = await this.transporter.sendMail({
        from,
        to,
        subject,
        html,
      });

      this.logger.log(`Email sent to ${to}: ${info.messageId}`);
      return info;
    } catch (error) {
      this.logger.error(`Failed to send email to ${to}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Envia um email de verificação de conta
   * @param to Email do destinatário
   * @param verificationLink Link de verificação
   * @returns Informações de envio
   */
  async sendVerificationEmail(to: string, verificationLink: string): Promise<any> {
    const subject = 'Verifique sua conta';
    const html = `
      <h1>Verificação de Conta</h1>
      <p>Olá,</p>
      <p>Obrigado por se registrar. Por favor, clique no link abaixo para verificar sua conta:</p>
      <p><a href="${verificationLink}">Verificar minha conta</a></p>
      <p>Se você não solicitou esta verificação, por favor ignore este email.</p>
      <p>Atenciosamente,<br>Equipe Visa Platform</p>
    `;

    return this.sendEmail(to, subject, html);
  }

  /**
   * Envia um email de redefinição de senha
   * @param to Email do destinatário
   * @param resetLink Link de redefinição
   * @returns Informações de envio
   */
  async sendPasswordResetEmail(to: string, resetLink: string): Promise<any> {
    const subject = 'Redefinição de Senha';
    const html = `
      <h1>Redefinição de Senha</h1>
      <p>Olá,</p>
      <p>Recebemos uma solicitação para redefinir sua senha. Por favor, clique no link abaixo para criar uma nova senha:</p>
      <p><a href="${resetLink}">Redefinir minha senha</a></p>
      <p>Este link expirará em 1 hora.</p>
      <p>Se você não solicitou esta redefinição, por favor ignore este email.</p>
      <p>Atenciosamente,<br>Equipe Visa Platform</p>
    `;

    return this.sendEmail(to, subject, html);
  }
} 