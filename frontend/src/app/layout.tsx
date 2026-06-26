import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'MSSP Lite — Threat Intelligence Map',
  description: 'Real-time threat intelligence for your server IP',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
