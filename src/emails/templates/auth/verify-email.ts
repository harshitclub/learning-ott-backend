export const verifyEmailTemplate = ({
  name,
  token
}: {
  name: string
  token: string
}) => {
  return `
    <html>
    <body>
    <h1>${name}</h1>
    <p>${token}</p>
    </body>
    </html>
    `
}
