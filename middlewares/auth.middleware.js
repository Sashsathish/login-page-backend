import jwt from 'jsonwebtoken';
import joi from 'joi';
export const authorizeMiddleware = (req, res, next) => {
  try {
    console.log('cookies', req.cookies);
    const token = req.cookies?.jwt;
    if (!token) {
      return res
        .status(401)
        .json({ message: 'no token found', error: 'unauthorized' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return res
        .status(401)
        .json({ message: 'invalid token', error: 'unauthorized' });
    }

    req.user = decoded;
    next();
  } catch (error) {
    console.log(error);
    return res
      .status(401)
      .json({ message: 'unauthorized', error: error.message });
  }
};
export const loginMiddleware = (req, res, next) => {
  const loginSchema = joi.object({
    email: joi.string().required().email().messages({
      'string.empty': 'email cannot be empty',
      'string.email': 'email must be a valid email',
    }),
    password: joi.string().required().min(6).messages({
      'string.empty': 'password cannot be empty',
      'string.min': 'password must be at least 6 characters long',
    }),
  });

  const { error } = loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      message: error.details[0].message,
      error: 'invalid credentials',
    });
  }
  next();
};

export const signupMiddleware = (req, res, next) => {
  const schema = joi.object({
    username: joi.string().required().max(30).min(3).messages({
      'string.empty': 'username cannot be empty',
      'string.min': 'username must be at least 3 characters long',

      'string.max': 'username must be at most 30 characters long',
    }),
    email: joi.string().required().email().messages({
      'string.empty': 'email cannot be empty',
      'string.email': 'email must be a valid email',
    }),
    password: joi.string().required().min(6).messages({
      'string.empty': 'password cannot be empty',
      'string.min': 'password must be at least 6 characters long',
    }),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      message: error.details[0].message,
      error: 'invalid credentials',
    });
  }
  next();
};
