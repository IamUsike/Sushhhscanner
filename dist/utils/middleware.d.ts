import { Request, Response, NextFunction } from 'express';
export declare const errorHandler: (err: any, req: Request, res: Response, next: NextFunction) => void;
export declare const notFound: (req: Request, res: Response, next: NextFunction) => void;
export declare const authenticate: (req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>>;
export declare const requireAdmin: (req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>>;
export declare const validateApiKey: (req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>>;
export declare const validateRequest: (schema: any) => (req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>>;
export declare const asyncHandler: (fn: Function) => (req: Request, res: Response, next: NextFunction) => void;
export declare const securityHeaders: (req: Request, res: Response, next: NextFunction) => void;
declare global {
    namespace Express {
        interface Request {
            user?: {
                id: string;
                email: string;
                role: string;
            };
        }
    }
}
//# sourceMappingURL=middleware.d.ts.map