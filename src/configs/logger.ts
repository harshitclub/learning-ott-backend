import winston from "winston";
import path from "path";
import { config } from "./config";

// Define log levels
const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define colors for console logs
const colors = {
  error: "red",
  warn: "yellow",
  info: "green",
  http: "magenta",
  debug: "blue",
};

winston.addColors(colors);

// Log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  winston.format.colorize({ all: true }),
  winston.format.printf(
    (info) => `[${info.timestamp}] ${info.level}: ${info.message}`
  )
);

// Helper to create a rotating file transport with size limit
const fileTransport = (level: string) =>
  new winston.transports.File({
    filename: path.join(__dirname, `../../logs/${level}.log`),
    level,
    maxsize: 1_000_000, // ~1MB ≈ roughly 2000 logs depending on length
    maxFiles: 1, // keep only one file (overwrite when full)
    tailable: true, // overwrite oldest logs first
  });

// Create logger instance
export const logger = winston.createLogger({
  level: config.LOG_LEVEL || "info",
  levels: logLevels,
  format: logFormat,
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
    fileTransport("error"),
    fileTransport("info"),
    fileTransport("http"),
  ],
});

// Morgan integration stream
export const loggerStream = {
  write: (message: string) => {
    logger.http(message.trim());
  },
};
