import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { config } from "../configs/config";
import { logger } from "../configs/logger";

dotenv.config();

const JWT_VERIFICATION_SECRET = config.JWT.VERIFICATION_SECRET;
const JWT_ACCESS_SECRET = config.JWT.ACCESS_SECRET;
const JWT_REFRESH_SECRET = config.JWT.REFRESH_SECRET;

/**
 * Generate a verification token (e.g., email verification, password reset)
 * @param payload - data to encode (e.g., userId, email)
 * @returns JWT token string (expires in 15 minutes)
 */
export const generateVerificationToken = (payload: object): string => {
  return jwt.sign(payload, JWT_VERIFICATION_SECRET, {
    expiresIn: "15m",
  });
};

/**
 * Verify a verification token
 * @param token - JWT token string
 * @returns decoded payload if valid
 * @throws error if invalid or expired
 */
export const verifyVerificationToken = (token: string) => {
  try {
    return jwt.verify(token, JWT_VERIFICATION_SECRET);
  } catch (err) {
    logger.error("Invalid or expired verification token");
    throw err;
  }
};

/**
 * Generate an access token (used for authenticating API requests)
 * @param payload - data to encode (e.g., userId, role)
 * @returns JWT token string (expires in 15 minutes)
 */
export const generateAccessToken = (payload: object): string => {
  return jwt.sign(payload, JWT_ACCESS_SECRET, {
    expiresIn: 3600, // 1 hour
  });
};

/**
 * Verify an access token
 * @param token - JWT token string
 * @returns decoded payload if valid
 * @throws error if invalid or expired
 */
export const verifyAccessToken = (token: string) => {
  try {
    return jwt.verify(token, JWT_ACCESS_SECRET);
  } catch (err) {
    logger.error("Invalid or expired access token");
    throw err;
  }
};

/**
 * Generate a refresh token (used to get new access token)
 * @param payload - data to encode (e.g., userId)
 * @returns JWT token string (expires in 7 days)
 */
export const generateRefreshToken = (payload: object): string => {
  return jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: 604800, // 7 days
  });
};

/**
 * Verify a refresh token
 * @param token - JWT token string
 * @returns decoded payload if valid
 * @throws error if invalid or expired
 */
export const verifyRefreshToken = (token: string) => {
  try {
    return jwt.verify(token, JWT_REFRESH_SECRET);
  } catch (err) {
    logger.error("Invalid or expired refresh token");
    throw err;
  }
};
