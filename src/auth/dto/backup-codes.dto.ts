import { ApiProperty } from '@nestjs/swagger';

export class BackupCodesResponseDto {
  @ApiProperty({
    description: 'Códigos de backup para acesso de emergência',
    example: ['ABCD1234', 'EFGH5678', 'IJKL9012'],
    type: [String],
  })
  backupCodes: string[];
} 