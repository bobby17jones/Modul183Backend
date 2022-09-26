import { Request, Response } from "express"
import { createTransport } from "nodemailer";
import connectDB from "../../ormconfig";
import { Reset } from "../entity/reset.entity";
import { User } from "../entity/user.entity";
import bcryptjs from "bcryptjs";
import { validationResult } from "express-validator";



export const ForgotPassword = async (req: Request, res: Response) => {
    const {email} = req.body;
    const token = Math.random().toString(20).substring(2, 12);
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).render("/api/forgot", {
            path: "/api/forgot",
            pageTitle: "Forgot Password",
            errors: errors.array()
        });
    }

    await connectDB.getRepository(Reset).save({
        email,
        token
    });

    const transporter = createTransport({
        host: '0.0.0.0',
        port: 1025
    });

    const url = `http://localhost:8080/reset/${token}`;

    await transporter.sendMail({
        from: 'example@example.com',
        to: email,
        subject: 'Reset your password',
        html: `<a href="${url}">Reset your password</a>`
    })
    

    res.send({
        message: 'Please check your email!'
    });
}

export const ResetPassword = async (req: Request, res: Response) => {
    const {token, password, password_confirm} = req.body;

    if (password !== password_confirm) {
        return res.status(400).send({
            message: "Password does not match"
        });
    } 

    const resetPassword = await connectDB.getRepository(Reset).findOne({
        where: {
            token
        }
    });

    if (!resetPassword) {
        return res.status(400).send({
            message: "Invalid token"
        });
    }

    const user = await connectDB.getRepository(User).findOne({
        where: {
            email: resetPassword.email
        }
    });

    if (!user) {
        return res.status(400).send({
            message: "User not found"
        });
    }

    await connectDB.getRepository(User).update(user.id, {
        password: await bcryptjs.hash(password, 10)
    });

    res.send({
        message: "Password has been reset"
    });
}