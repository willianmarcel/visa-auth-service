import { ApiProperty } from '@nestjs/swagger';

export class GenerateMfaResponseDto {
  @ApiProperty({
    description: 'ID temporário para configuração do MFA',
    example: 'd7c2c5a0-3b7b-4b5c-9c0e-5d1b1b2c3d4e',
  })
  tempId: string;

  @ApiProperty({
    description: 'Segredo TOTP para configuração manual',
    example: 'JBSWY3DPEHPK3PXP',
  })
  secret: string;

  @ApiProperty({
    description: 'URL do QR code para escanear com o aplicativo autenticador',
    example: 'data:image/png;base64,iVBOR...',
  })
  qrCodeUrl: string;
} 