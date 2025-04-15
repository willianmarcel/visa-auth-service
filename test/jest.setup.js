const path = require('path');
const dotenv = require('dotenv');

// Carregar variáveis de ambiente do arquivo .env.test
dotenv.config({ path: path.resolve(__dirname, '.env.test') });

// Mock do serviço de email para evitar envios reais durante os testes
jest.mock('../src/email/email.service', () => {
  return {
    EmailService: jest.fn().mockImplementation(() => ({
      initializeTransporter: jest.fn(),
      sendEmail: jest.fn().mockResolvedValue({ messageId: 'test-message-id' }),
      sendVerificationEmail: jest.fn().mockResolvedValue({ messageId: 'test-message-id' }),
      sendPasswordResetEmail: jest.fn().mockResolvedValue({ messageId: 'test-message-id' }),
    })),
  };
}); 