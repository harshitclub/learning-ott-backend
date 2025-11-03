import express from 'express'
import {
  userLogin,
  userProfile,
  userSignup,
  userUpdate
} from '../../controllers/user.controllers'

const userRoutesV1 = express.Router()

userRoutesV1.post('/signup', userSignup)
userRoutesV1.post('/login', userLogin)
userRoutesV1.get('/me', userProfile)
userRoutesV1.patch('/me', userUpdate)

export default userRoutesV1
