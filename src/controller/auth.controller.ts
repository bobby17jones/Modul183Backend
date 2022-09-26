import { Request, Response } from "express";
import connectDB from "../../ormconfig";
import { User } from "../entity/user.entity";
import bcryptjs from "bcryptjs";
import { sign, verify } from "jsonwebtoken";
import { Token } from "../entity/token.entity";
import { MoreThanOrEqual } from "typeorm";
import { validationResult } from "express-validator";

const speakeasy = require("speakeasy");
const qrcode = require("qrcode");

export const Register = async (req: Request, res: Response) => {
    const body = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).render("/api/register", {
            path: "/api/register",
            pageTitle: "Register",
            errors: errors.array()
        });
    }

    if (body.password !== body.password_confirm) {
        return res.status(400).send({
            message: "Password does not match"
        });
    }                                

    const {password, tfa_secret, ...user} = await connectDB.getRepository(User).save({
        first_name: body.first_name,
        last_name: body.last_name,
        email: body.email,
        password: await bcryptjs.hash(body.password, 10)
    });

    res.send(user);
};

export const Login = async (req: Request, res: Response) => {
    const body = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).render("/api/login", {
            path: "/api/login",
            pageTitle: "Login",
            errors: errors.array()
        });
    }

    const user = await connectDB.getRepository(User).findOne({
        where: {
        email: body.email
        }
    });

    if (!user) {
        return res.status(400).send({
            message: "User not found"
        });
    }

    if (!await bcryptjs.compare(req.body.password, user.password)) {
        return res.status(400).send({
            message: "Password is incorrect"
        });

    }

    if (user.tfa_secret) {
        return res.send({
            id: user.id,
        });
    }

    const secret = speakeasy.generateSecret({
        name: "2FA",
        length: 20
    });

    res.send({
        id: user.id,
        secret: secret.ascii,
        otpauth_url: secret.otpauth_url
    });
};


export const TwoFactorAuth = async (req: Request, res: Response) => {
    try {
    const id = req.body.id;

    const repository = await connectDB.getRepository(User);

    const user = await repository.findOne({
        where: {
            id
        }
    });

    if (!user) {
        return res.status(400).send({
            message: "User not found"
        });
    }

    const secret = user.tfa_secret !== '' ? user.tfa_secret : req.body.secret;

    const verified = speakeasy.totp.verify({
        secret,
        encoding: "ascii",
        token: req.body.code
    });

    if (!verified) {
        return res.status(400).send({
            message: "Invalid code"
        });
    }

    if (user.tfa_secret === '') {
        await repository.update(id, {
            tfa_secret: secret
        });
    }

    const refreshToken = sign({
        id
    }, process.env.REFRESH_SECRET || '', {expiresIn: "1w"});


    res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        maxAge: 7*24*60*60*1000 //1 week
    });

    const expired_at = new Date();
    expired_at.setDate(expired_at.getDate() + 7);

    await connectDB.getRepository(Token).save({
        user_id: id,
        token: refreshToken,
        expired_at
    });

    const token = sign({
        id
    }, process.env.ACCESS_SECRET || '', {expiresIn: "30s"});

    res.send({
        token
    });
    } catch (error) {
        return res.status(401).send({
            message: "Unauthorized"
    });
    }
};


export const AuthenticatedUser = async (req: Request, res: Response) => {
    try {
        const refreshToken = req.cookies.refresh_token;

        if (!refreshToken) {
            return res.status(401).send({
                message: "No refresh token"
            });
        }

        const payload: any = verify(refreshToken, process.env.REFRESH_SECRET || '');

        if (!payload) {
            return res.status(401).send({
                message: "No payload"
            });
        }

        const token = await connectDB.getRepository(Token).findOne({
            where: {
                user_id: payload.id,
                token: refreshToken,
                expired_at: MoreThanOrEqual(new Date())
            }
        });

        if (!token) {
            return res.status(401).send({
                message: "No token in database"
            });
        }

        const user = await connectDB.getRepository(User).findOne({
            where: {
                id: payload.id
            }
        });

        if (!user) {
            return res.status(401).send({
                message: "No user"
            });
        }

        const {password, tfa_secret, ...data} = user;

        res.send(data);

    } catch (error) {
        return res.status(401).send({
            message: "Du spast"
        });
    }
};

export const Refresh = async (req: Request, res: Response) => {
    try {
        const cookie = req.cookies.refresh_token;

        const payload: any = verify(cookie, process.env.REFRESH_SECRET || '');

        if (!payload) {
            return res.status(401).send({
                message: "Unauthorized"
            });
        }

        const refreshToken = await connectDB.getRepository(Token).findOne({
            where: {
                user_id: payload.id,
                expired_at: MoreThanOrEqual(new Date())
            }
        });

        if (!refreshToken) {
            return res.status(401).send({
                message: "Unauthorized"
            });
        }

        const token = sign({
            id: payload.id
        }, process.env.ACCESS_SECRET || '', {expiresIn: "30s"});

        res.send({
            token
        });

    } catch (error) {
        return res.status(401).send({
            message: "Unauthorized"
        });
    }
};

export const Logout = async (req: Request, res: Response) => {
    const refreshToken = req.cookies.refresh_token;

    await connectDB.getRepository(Token).delete({
        token: refreshToken
    });


    res.cookie('refresh_token', '', {maxAge: 0});

    res.send({
        message: 'success'
    });
};
