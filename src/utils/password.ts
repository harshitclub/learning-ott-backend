import bcrypt from "bcrypt";
import { config } from "../configs/config";

/**
 * Hash a plain text password
 * @param password - user entered plain password
 * @returns hashed password
 */

export const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = config.BCRYPT_SALT_ROUNDS; // default 10
  return await bcrypt.hash(password, saltRounds);
};

/**
 * Compare plain password with hashed password
 * @param password - plain password from login input
 * @param hashedPassword - password stored in DB
 * @returns boolean (true if match, false otherwise)
 */

export const comparePassword = async (
  password: string,
  hashedPassword: string
): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword);
};
