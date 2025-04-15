import { IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResetPasswordDto {
  @ApiProperty({
    description: 'Token de redefinição de senha',
    example: 'abcdef123456',
  })
  @IsString({ message: 'O token deve ser uma string' })
  @IsNotEmpty({ message: 'Token é obrigatório' })
  token: string;

  @ApiProperty({
    description: 'Nova senha do usuário',
    example: 'Senha@123',
  })
  @IsString({ message: 'A senha deve ser uma string' })
  @MinLength(8, { message: 'A senha deve ter pelo menos 8 caracteres' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/, {
    message: 'A senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial',
  })
  @IsNotEmpty({ message: 'Nova senha é obrigatória' })
  password: string;

  @ApiProperty({
    description: 'Confirmação da nova senha',
    example: 'Senha@123',
  })
  @IsString({ message: 'A confirmação da senha deve ser uma string' })
  @IsNotEmpty({ message: 'Confirmação de senha é obrigatória' })
  confirmPassword: string;
} 