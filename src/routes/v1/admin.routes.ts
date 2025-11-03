import express from 'express'
import {
  adminLogin,
  adminProfile,
  adminSignup,
  adminUpdate
} from '../../controllers/admin.controllers'

const adminRoutesV1 = express.Router()

adminRoutesV1.post('/signup', adminSignup)
adminRoutesV1.post('/login', adminLogin)
adminRoutesV1.get('/me', adminProfile)
adminRoutesV1.patch('/me', adminUpdate)

export default adminRoutesV1
