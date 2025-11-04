import express from 'express'
import { asyncHandler } from '../../middlewares/asyncHandler'
import {
  checkHealth,
  getAppInfo,
  getMemoryUsage,
  getServerTime,
  getUptime,
  ping
} from '../../controllers/v1/system.controllers'

const systemRoutesV1 = express.Router()

systemRoutesV1.get('/health', asyncHandler(checkHealth))
systemRoutesV1.get('/info', asyncHandler(getAppInfo))
systemRoutesV1.get('/time', asyncHandler(getServerTime))
systemRoutesV1.get('/ping', asyncHandler(ping))
systemRoutesV1.get('/uptime', asyncHandler(getUptime))
systemRoutesV1.get('/memory', asyncHandler(getMemoryUsage))

export default systemRoutesV1
