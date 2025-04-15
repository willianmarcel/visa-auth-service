import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm';
import { Exclude } from 'class-transformer';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  @Exclude()
  password: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column({ nullable: true })
  profilePicture: string;

  @Column({ default: false })
  emailVerified: boolean;

  @Column({ nullable: true })
  mfaEnabled: boolean;

  @Column({ nullable: true })
  mfaSecret: string;

  @Column('simple-array', { default: [] })
  roles: string[];

  @Column({ nullable: true })
  googleId: string;

  @Column({ nullable: true })
  linkedinId: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
} 