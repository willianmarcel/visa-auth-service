import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { PasswordUtils } from '../../auth/utils/password.util';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  /**
   * Encontra um usuário pelo email
   * @param email Email do usuário
   * @returns User ou undefined
   */
  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  /**
   * Encontra um usuário pelo ID
   * @param id ID do usuário
   * @returns User ou undefined
   */
  async findById(id: string): Promise<User | null> {
    return this.userRepository.findOneBy({ id });
  }

  /**
   * Cria um novo usuário
   * @param userData Dados do usuário
   * @returns Usuário criado
   */
  async create(userData: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    profilePicture?: string;
  }): Promise<User> {
    const existingUser = await this.findByEmail(userData.email);
    if (existingUser) {
      throw new ConflictException('Email já está em uso');
    }

    const hashedPassword = await PasswordUtils.hash(userData.password);

    const user = this.userRepository.create({
      ...userData,
      password: hashedPassword,
      roles: ['user'],
    });

    return this.userRepository.save(user);
  }

  /**
   * Atualiza um usuário existente
   * @param id ID do usuário
   * @param userData Dados a serem atualizados
   * @returns Usuário atualizado
   */
  async update(
    id: string,
    userData: Partial<{
      firstName: string;
      lastName: string;
      profilePicture: string;
    }>,
  ): Promise<User> {
    const user = await this.findById(id);
    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    Object.assign(user, userData);
    return this.userRepository.save(user);
  }

  /**
   * Atualiza a senha de um usuário
   * @param id ID do usuário
   * @param currentPassword Senha atual
   * @param newPassword Nova senha
   * @returns True se a senha foi atualizada com sucesso
   */
  async updatePassword(
    id: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<boolean> {
    const user = await this.findById(id);
    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    const isPasswordValid = await PasswordUtils.validate(currentPassword, user.password);
    if (!isPasswordValid) {
      return false;
    }

    const hashedPassword = await PasswordUtils.hash(newPassword);
    user.password = hashedPassword;
    await this.userRepository.save(user);

    return true;
  }
} 