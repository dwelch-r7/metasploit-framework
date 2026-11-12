export default function protectedResource(request, response) {
  response.status(200).json({ resource: 'PRIVATE MODULE TARGET API' })
}
