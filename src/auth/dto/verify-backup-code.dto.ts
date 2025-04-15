import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class VerifyBackupCodeDto {
  @ApiProperty({
    description: 'Código de backup para autenticação',
    example: 'ABCD1234',
  })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({
    description: 'ID da sessão temporária (recebido durante o login)',
    example: 'd7c2c5a0-3b7b-4b5c-9c0e-5d1b1b2c3d4e',
  })
  @IsString()
  @IsNotEmpty()
  sessionId: string;
} 