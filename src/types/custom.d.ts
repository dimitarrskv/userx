declare namespace Express {
    interface Request {
        auth: any;
        token: string;
    }
}