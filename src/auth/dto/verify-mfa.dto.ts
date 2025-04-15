import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class VerifyMfaDto {
  @ApiProperty({
    description: 'Token TOTP de verificação',
    example: '123456',
  })
  @IsString()
  @IsNotEmpty()
  token: string;

  @ApiProperty({
    description: 'ID da sessão temporária (recebido durante o login)',
    example: 'd7c2c5a0-3b7b-4b5c-9c0e-5d1b1b2c3d4e',
  })
  @IsString()
  @IsNotEmpty()
  sessionId: string;
} 