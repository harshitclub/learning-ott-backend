import express from 'express'
import {
  userLogin,
  userProfile,
  userSignup,
  userUpdate
} from '../../controllers/user.controllers'
import { asyncHandler } from '../../middlewares/asyncHandler'

const userRoutesV1 = express.Router()

userRoutesV1.post('/signup', asyncHandler(userSignup))
userRoutesV1.post('/login', asyncHandler(userLogin))
userRoutesV1.get('/me', asyncHandler(userProfile))
userRoutesV1.patch('/me', asyncHandler(userUpdate))

export default userRoutesV1
