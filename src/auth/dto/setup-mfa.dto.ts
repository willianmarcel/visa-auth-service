import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class SetupMfaDto {
  @ApiProperty({
    description: 'Token TOTP de verificação',
    example: '123456',
  })
  @IsString()
  @IsNotEmpty()
  token: string;
} 