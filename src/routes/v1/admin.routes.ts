import express from 'express'

const adminRouter = express.Router()

adminRouter.post('/signup', () => {})
adminRouter.post('/login', () => {})
adminRouter.get('/me', () => {})
adminRouter.patch('/me', () => {})

export default adminRouter
