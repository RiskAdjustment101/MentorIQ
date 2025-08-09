import { UserProvider } from '@auth0/nextjs-auth0/client';
import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'MentorIQ - AI-Powered FLL Mentoring',
  description: 'COPPA-compliant, parent-controlled mentoring platform for FIRST Lego League teams',
  keywords: 'FLL, FIRST Lego League, mentoring, AI, COPPA, parent-controlled, children safety',
  authors: [{ name: 'MentorIQ Team' }],
  robots: 'index, follow',
  viewport: 'width=device-width, initial-scale=1',
  
  // Security meta tags
  other: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  }
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <UserProvider>
          {children}
        </UserProvider>
      </body>
    </html>
  );
}