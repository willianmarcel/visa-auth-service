import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../src/users/entities/user.entity';
import { TokenService } from '../src/auth/services/token.service';
import { PasswordUtils } from '../src/auth/utils/password.util';

describe('PasswordReset (e2e)', () => {
  let app: INestApplication;
  let userRepository: Repository<User>;
  let tokenService: TokenService;
  let testUser: User;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    
    userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));
    tokenService = moduleFixture.get<TokenService>(TokenService);
    
    await app.init();
    
    // Criar um usuário de teste
    const password = await PasswordUtils.hash('Teste@123');
    testUser = await userRepository.save({
      email: 'test@example.com',
      password,
      firstName: 'Test',
      lastName: 'User',
      emailVerified: true,
    });
  });

  afterAll(async () => {
    // Limpar o usuário de teste
    if (testUser) {
      await userRepository.delete(testUser.id);
    }
    await app.close();
  });

  describe('POST /auth/request-password-reset', () => {
    it('deve retornar 200 para um email válido', () => {
      return request(app.getHttpServer())
        .post('/auth/request-password-reset')
        .send({ email: 'test@example.com' })
        .expect(200)
        .expect(res => {
          expect(res.body.message).toBeDefined();
        });
    });

    it('deve retornar 200 mesmo para um email não registrado (por segurança)', () => {
      return request(app.getHttpServer())
        .post('/auth/request-password-reset')
        .send({ email: 'nonexistent@example.com' })
        .expect(200)
        .expect(res => {
          expect(res.body.message).toBeDefined();
        });
    });

    it('deve retornar 400 para uma requisição com dados inválidos', () => {
      return request(app.getHttpServer())
        .post('/auth/request-password-reset')
        .send({ email: 'invalid-email' })
        .expect(400);
    });
  });

  describe('POST /auth/reset-password', () => {
    it('deve redefinir a senha com um token válido', async () => {
      // Gerar um token válido
      const token = await tokenService.generatePasswordResetToken(testUser.id);

      return request(app.getHttpServer())
        .post('/auth/reset-password')
        .send({
          token,
          password: 'NovaSenha@123',
          confirmPassword: 'NovaSenha@123'
        })
        .expect(200)
        .expect(res => {
          expect(res.body.message).toBe('Senha redefinida com sucesso');
        });
    });

    it('deve retornar 400 quando as senhas não coincidem', async () => {
      const token = await tokenService.generatePasswordResetToken(testUser.id);

      return request(app.getHttpServer())
        .post('/auth/reset-password')
        .send({
          token,
          password: 'Senha@123',
          confirmPassword: 'SenhaErrada@123'
        })
        .expect(400);
    });

    it('deve retornar 400 para um token inválido', () => {
      return request(app.getHttpServer())
        .post('/auth/reset-password')
        .send({
          token: 'token-invalido',
          password: 'Senha@123',
          confirmPassword: 'Senha@123'
        })
        .expect(400);
    });

    it('deve retornar 400 para uma senha que não atende aos requisitos', async () => {
      const token = await tokenService.generatePasswordResetToken(testUser.id);

      return request(app.getHttpServer())
        .post('/auth/reset-password')
        .send({
          token,
          password: 'senha123', // sem maiúscula e caractere especial
          confirmPassword: 'senha123'
        })
        .expect(400);
    });
  });
}); 