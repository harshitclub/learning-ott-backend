import express from 'express'
import {
  adminChangePassword,
  adminLogin,
  adminProfile,
  adminSignup,
  adminUpdate,
  adminVerifyEmail,
  refreshHandler
} from '../../controllers/v1/admin.controllers'
import { asyncHandler } from '../../middlewares/asyncHandler'

const adminRoutesV1 = express.Router()

adminRoutesV1.post('/signup', asyncHandler(adminSignup))
adminRoutesV1.get('/verify', asyncHandler(adminVerifyEmail))
adminRoutesV1.post('/login', asyncHandler(adminLogin))
adminRoutesV1.get('/me', asyncHandler(adminProfile))
adminRoutesV1.patch('/me', asyncHandler(adminUpdate))
adminRoutesV1.post('/refresh', asyncHandler(refreshHandler))
adminRoutesV1.patch('/change-password', asyncHandler(adminChangePassword))

export default adminRoutesV1
