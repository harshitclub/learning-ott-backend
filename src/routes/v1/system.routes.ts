import express from 'express'
import { asyncHandler } from '../../middlewares/asyncHandler'
import {
  checkHealth,
  getAppInfo,
  getMemoryUsage,
  getServerTime,
  getUptime,
  ping
} from '../../controllers/system.controllers'

const healthRoutes = express.Router()

healthRoutes.get('/health', asyncHandler(checkHealth))
healthRoutes.get('/info', asyncHandler(getAppInfo))
healthRoutes.get('/time', asyncHandler(getServerTime))
healthRoutes.get('/ping', asyncHandler(ping))
healthRoutes.get('/uptime', asyncHandler(getUptime))
healthRoutes.get('/memory', asyncHandler(getMemoryUsage))

export default healthRoutes
