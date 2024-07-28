import { prisma } from '../prisma/index.js';
import nodemailer from 'nodemailer';
import bcryptjs from 'bcryptjs';

export const salt = bcryptjs.genSaltSync(10);

const transport = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});

console.log(process.env.EMAIL);
export const findUser = async (email) => {
  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  return user;
};

export const sendEmail = async (email, subject, text) => {
  return await transport.sendMail({
    from: process.env.EMAIL,
    to: email,
    subject: subject,
    text: text,
  });
};

export const sendOtpEmail = async (email, otp) => {
  console.log(email, otp);
  let mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}. It will expire in 10 minutes.`,
  };
  return await transport.sendMail(mailOptions);
};

export const generateOtp = () => {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  return otp;
};
export const otpExpiryTime = 1000 * 60 * 2;
