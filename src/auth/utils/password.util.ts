import * as bcrypt from 'bcrypt';

export class PasswordUtils {
  private static readonly SALT_ROUNDS = 10;

  /**
   * Gera um hash da senha fornecida
   * @param password Senha em texto puro
   * @returns String hash da senha
   */
  static async hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.SALT_ROUNDS);
  }

  /**
   * Verifica se a senha fornecida corresponde ao hash
   * @param password Senha em texto puro
   * @param hashedPassword Hash armazenado
   * @returns Boolean indicando se a senha é válida
   */
  static async validate(password: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }
} 