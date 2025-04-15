import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Adiciona validação global para DTOs
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Configuração de CORS
  app.enableCors({
    origin: true,
    credentials: true,
  });

  // Prefixo global para as rotas da API
  app.setGlobalPrefix('api');

  // Obtém a porta do serviço de configuração
  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT', 3001);

  await app.listen(port);
  console.log(`Aplicação rodando na porta: ${port}`);
}
bootstrap();
