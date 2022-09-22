import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from "typeorm";

@Entity()
export class Token {
    @PrimaryGeneratedColumn()
    id!: number;

    @Column()
    user_id!: number;

    @Column()
    token!: string;

    @CreateDateColumn()
    created_at!: Date;

    @Column()
    expired_at!: Date;
}