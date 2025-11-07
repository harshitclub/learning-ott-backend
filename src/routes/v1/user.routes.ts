import express from 'express'
import {
  refreshHandler,
  userLogin,
  userProfile,
  userSignup,
  userUpdate,
  userVerifyEmail
} from '../../controllers/v1/user.controllers'
import { asyncHandler } from '../../middlewares/asyncHandler'

const userRoutesV1 = express.Router()

userRoutesV1.post('/signup', asyncHandler(userSignup))
userRoutesV1.get('/verify', asyncHandler(userVerifyEmail))
userRoutesV1.post('/login', asyncHandler(userLogin))
userRoutesV1.get('/me', asyncHandler(userProfile))
userRoutesV1.patch('/me', asyncHandler(userUpdate))
userRoutesV1.post('/refresh', asyncHandler(refreshHandler))

export default userRoutesV1
