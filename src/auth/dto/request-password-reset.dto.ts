import { IsEmail, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RequestPasswordResetDto {
  @ApiProperty({
    description: 'Email do usuário que deseja redefinir a senha',
    example: 'usuario@example.com',
  })
  @IsEmail({}, { message: 'Forneça um email válido' })
  @IsNotEmpty({ message: 'Email é obrigatório' })
  email: string;
} 