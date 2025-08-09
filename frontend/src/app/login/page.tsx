'use client';

import { useUser } from '@auth0/nextjs-auth0/client';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import Link from 'next/link';
import { ShieldCheckIcon, UserGroupIcon, LockClosedIcon } from '@heroicons/react/24/outline';

export default function LoginPage() {
  const { user, isLoading } = useUser();
  const router = useRouter();

  useEffect(() => {
    // Redirect if already logged in
    if (user && !isLoading) {
      router.push('/parent/dashboard');
    }
  }, [user, isLoading, router]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-blue-100 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        {/* Logo */}
        <div className="flex justify-center">
          <div className="flex items-center space-x-2">
            <UserGroupIcon className="h-12 w-12 text-primary-600" />
            <h1 className="text-3xl font-bold text-gray-900">MentorIQ</h1>
          </div>
        </div>
        
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
          Parent Portal
        </h2>
        <p className="mt-2 text-center text-sm text-gray-600">
          Secure access to manage your child's FLL mentoring journey
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
          
          {/* COPPA Compliance Notice */}
          <div className="mb-6 p-4 bg-safety-50 border border-safety-200 rounded-lg">
            <div className="flex">
              <ShieldCheckIcon className="h-5 w-5 text-safety-600 mt-0.5" />
              <div className="ml-3">
                <h3 className="text-sm font-medium text-safety-800">
                  Child Safety First
                </h3>
                <div className="mt-1 text-sm text-safety-700">
                  <ul className="list-disc list-inside space-y-1">
                    <li>Only parents/guardians can create accounts</li>
                    <li>Children cannot register directly</li>
                    <li>You control all your child's data</li>
                    <li>AI-powered safety monitoring</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            {/* Login Button */}
            <div>
              <a
                href="/api/auth/login?returnTo=/parent/dashboard"
                className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 transition-colors"
              >
                <LockClosedIcon className="h-5 w-5 mr-2" />
                Sign In Securely
              </a>
            </div>

            {/* Registration Link */}
            <div className="text-center">
              <p className="text-sm text-gray-600">
                New parent?{' '}
                <Link 
                  href="/register" 
                  className="font-medium text-primary-600 hover:text-primary-500"
                >
                  Create your parent account
                </Link>
              </p>
            </div>

            {/* Divider */}
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-gray-500">Learn about our safety</span>
              </div>
            </div>

            {/* Safety Features */}
            <div className="grid grid-cols-1 gap-4 text-center">
              <div className="p-3 bg-gray-50 rounded-lg">
                <h4 className="font-medium text-gray-900 text-sm">COPPA Compliant</h4>
                <p className="text-xs text-gray-600 mt-1">
                  Full compliance with children's privacy laws
                </p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <h4 className="font-medium text-gray-900 text-sm">AI Safety Monitoring</h4>
                <p className="text-xs text-gray-600 mt-1">
                  Constitutional AI ensures appropriate interactions
                </p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <h4 className="font-medium text-gray-900 text-sm">Parent Controlled</h4>
                <p className="text-xs text-gray-600 mt-1">
                  You approve all mentors and activities
                </p>
              </div>
            </div>
          </div>

          {/* Footer Links */}
          <div className="mt-6 text-center space-y-2 text-xs text-gray-500">
            <div className="flex justify-center space-x-4">
              <Link href="/privacy" className="hover:text-gray-700">
                Privacy Policy
              </Link>
              <Link href="/coppa" className="hover:text-gray-700">
                COPPA Information
              </Link>
              <Link href="/ai-principles" className="hover:text-gray-700">
                AI Safety
              </Link>
            </div>
            <p>© 2024 MentorIQ. Built with Constitutional AI principles.</p>
          </div>
        </div>
      </div>
    </div>
  );
}