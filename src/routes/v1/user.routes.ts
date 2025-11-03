import express from 'express'

const userRouter = express.Router()

userRouter.post('/signup', () => {})
userRouter.post('/login', () => {})
userRouter.get('/me', () => {})
userRouter.patch('/me', () => {})

export default userRouter
