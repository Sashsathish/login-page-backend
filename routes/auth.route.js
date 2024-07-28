import { Router } from 'express';

import {
  signupMiddleware,
  loginMiddleware,
  authorizeMiddleware,
} from '../middlewares/auth.middleware.js';
import {
  signupController,
  loginController,
  logoutController,
  checkAuthStatusController,
  forgotPasswordController,
  resetPasswordController,
  resendOtpController,
  verifyOptController,
} from '../controllers/auth.controller.js';
const app = Router();

app.post('/signup', signupMiddleware, signupController);

app.post('/login', loginMiddleware, loginController);

app.post('/verify-otp', verifyOptController);

app.post('/resend-otp', resendOtpController);

app.get('/logout', authorizeMiddleware, logoutController);

app.get('/checkStatus', checkAuthStatusController);

app.post('/forgot-password', forgotPasswordController);

app.post('/reset-password', resetPasswordController);

export default app;
