import express from 'express'
import {
  adminLogin,
  adminProfile,
  adminSignup,
  adminUpdate
} from '../../controllers/admin.controllers'
import { asyncHandler } from '../../middlewares/asyncHandler'

const adminRoutesV1 = express.Router()

adminRoutesV1.post('/signup', asyncHandler(adminSignup))
adminRoutesV1.post('/login', asyncHandler(adminLogin))
adminRoutesV1.get('/me', asyncHandler(adminProfile))
adminRoutesV1.patch('/me', asyncHandler(adminUpdate))

export default adminRoutesV1
