import Redis from "ioredis";
import { config } from "./config";
import { logger } from "./logger";

/**
 * @client redisCache
 * @desc   Redis client dedicated for application-level caching
 * @usage  Store and retrieve frequently accessed data (e.g. user profiles, tokens)
 * @connection Uses config.REDIS.CACHE_URL from environment variables
 *
 * @example
 * // Save data with TTL
 * await redisCache.set("user:123", JSON.stringify(user), "EX", 3600);
 *
 * // Retrieve cached data
 * const cachedUser = await redisCache.get("user:123");
 * if (cachedUser) {
 *   return JSON.parse(cachedUser);
 * }
 */

const redisCache = new Redis(config.REDIS.CACHE_URL);

/**
 * @event connect
 * @desc  Fired when TCP connection to Redis is successfully established
 */
redisCache.on("connect", () => {
  logger.info(`Redis cache client connected: ${config.REDIS.CACHE_URL}`);
});

/**
 * @event ready
 * @desc  Fired when Redis is fully ready to accept commands (after handshake/auth)
 */
redisCache.on("ready", () => {
  logger.info("Redis cache is ready to accept commands");
});

/**
 * @event error
 * @desc  Fired when there is any Redis error (connection or command issue)
 */
redisCache.on("error", (err) => {
  logger.error(`Redis cache error: ${err.message}`);
});

/**
 * @event close
 * @desc  Fired when the connection to Redis is closed
 */
redisCache.on("close", () => {
  logger.info("Redis connection closed");
});

/**
 * @event reconnecting
 * @desc  Fired when the client is trying to reconnect (auto-retry mechanism)
 */
redisCache.on("reconnecting", () => {
  logger.info("Redis client reconnecting...");
});

export default redisCache;
