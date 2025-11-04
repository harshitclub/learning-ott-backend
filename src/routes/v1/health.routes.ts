import express from 'express'
import { asyncHandler } from '../../middlewares/asyncHandler'
import { checkHealth } from '../../controllers/health.controllers'

const healthRoutes = express.Router()

healthRoutes.get('/health', asyncHandler(checkHealth))

export default healthRoutes
