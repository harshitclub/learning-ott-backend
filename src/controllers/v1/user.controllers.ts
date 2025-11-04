import { Request, Response } from 'express'
import { ApiResponse } from '../../utils/apiResponse'

export async function userSignup(req: Request, res: Response) {
  const user = {
    name: 'Harshit Kumar',
    email: 'harshitclub@gmail.com'
  }
  return ApiResponse.success(
    req,
    res,
    200,
    'User registered successfully',
    user
  )
}
export async function userLogin() {}
export async function userProfile() {}
export async function userUpdate() {}
export async function userChangePassword() {}
