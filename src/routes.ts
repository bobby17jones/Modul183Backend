import { Router } from "express";
import { check } from "express-validator";
import { Register, Login, AuthenticatedUser, Refresh, Logout, TwoFactorAuth } from "./controller/auth.controller";
import { ForgotPassword, ResetPassword } from "./controller/reset.controller";


export const routes = (router: Router) => {
    router.post( '/api/register', 
        [
    check("first_name").isLength({ min: 3 }),
    check("last_name").isLength({ min: 3 }),
    check("email").isEmail(),
    check("password").isLength({ min: 6 }),
    check("password_confirm").custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error("Password confirmation does not match password");
        }
        return true;
    }),
    ], Register);
    router.post('/api/login', 
        [
    check("email").isEmail(),
    check("password").isLength({ min: 6 }),
    ], Login);

    router.post('/api/two-factor', TwoFactorAuth);
    router.get('/api/user', AuthenticatedUser);
    router.post('/api/refresh', Refresh);
    router.post('/api/logout', Logout);
    router.post('/api/forgot',
        [
    check("email").isEmail(),
    ], ForgotPassword);
    router.post('api/reset', ResetPassword);
}