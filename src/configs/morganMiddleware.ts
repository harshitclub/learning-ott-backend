import morgan from 'morgan'
import { loggerStream } from './logger'

// custom format for morgan logs
export const morganMiddleware = morgan(
  '[:date[iso]] :method :url :status :res[content-length] - :response-time ms',
  { stream: loggerStream }
)
