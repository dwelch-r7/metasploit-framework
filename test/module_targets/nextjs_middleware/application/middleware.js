import { NextResponse } from 'next/server'

export function middleware(request) {
  if (request.cookies.get('session')?.value === 'module-target-next-session') {
    return NextResponse.next()
  }

  let response
  if (request.nextUrl.pathname === '/api/protected') {
    response = NextResponse.json({ error: 'Authentication required' }, { status: 401 })
  } else if (request.nextUrl.pathname === '/forbidden') {
    response = NextResponse.json({ error: 'Authorization required' }, { status: 403 })
  } else {
    const status = request.nextUrl.pathname === '/redirect302' ? 302 : 307
    response = NextResponse.redirect(new URL('/login', request.url), status)
  }
  response.headers.set('x-module-target-gate', 'enforced')
  return response
}

export const config = {
  matcher: ['/dashboard/:path*', '/api/protected', '/forbidden', '/redirect302']
}
