'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { motion } from 'framer-motion';
import { Shield, CheckCircle, XCircle, Loader2 } from 'lucide-react';
import Link from 'next/link';
import CyberGrid from '@/components/ui/CyberGrid';

export default function VerifyEmailPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get('token');

  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    if (!token) {
      setStatus('error');
      setErrorMessage('Verification token is missing from the URL.');
      return;
    }

    const verifyToken = async () => {
      try {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'}/api/v1/auth/verify-email?token=${token}`, {
          method: 'GET',
        });

        const data = await res.json();

        if (!res.ok) {
          throw new Error(data.detail || 'Verification failed');
        }

        setStatus('success');
      } catch (err: any) {
        setStatus('error');
        setErrorMessage(err.message || 'An error occurred during verification.');
      }
    };

    verifyToken();
  }, [token]);

  return (
    <div className="min-h-screen bg-surface-0 flex flex-col justify-center py-12 px-6 lg:px-8 relative text-white">
      {/* Background Effect */}
      <div className="fixed inset-0 z-0">
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat transition-opacity duration-[2000ms]"
          style={{
            backgroundImage: "url('/bg/control.jpg')",
            opacity: 0.25,
          }}
        />
        <div className="absolute inset-0 bg-surface-0/80" />
      </div>
      
      <CyberGrid opacity={0.08} />

      <div className="sm:mx-auto sm:w-full sm:max-w-md relative z-10">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center"
        >
          <div className="w-16 h-16 mx-auto rounded-xl bg-gradient-to-br from-ghost-500 to-cyber-600 flex items-center justify-center shadow-lg shadow-ghost-500/20 mb-6 relative">
            <div className="absolute inset-0 border border-white/20 rounded-xl" />
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h2 className="text-3xl font-bold tracking-tight mb-2">Email Verification</h2>
          <p className="text-gray-400 text-sm mb-8">
            Establishing secure connection...
          </p>

          <div className="glass-card p-8 text-center space-y-6">
            {status === 'loading' && (
              <motion.div 
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex flex-col items-center justify-center space-y-4"
              >
                <Loader2 className="w-12 h-12 text-ghost-400 animate-spin" />
                <p className="text-[10px] font-semibold text-ghost-400 uppercase tracking-[0.2em]">
                  Decrypting Token...
                </p>
              </motion.div>
            )}

            {status === 'success' && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="flex flex-col items-center justify-center space-y-4"
              >
                <CheckCircle className="w-16 h-16 text-emerald-400" />
                <h3 className="text-xl font-bold text-white">Access Granted</h3>
                <p className="text-sm text-gray-400">
                  Your identity has been verified. Welcome to GhostPrompt.
                </p>
                <Link
                  href="/auth/login"
                  className="btn-primary w-full mt-4 flex justify-center py-2.5 group"
                >
                  <span className="relative z-10 font-bold tracking-wide text-sm group-hover:text-white transition-colors">
                    INITIATE LOGIN SEQUENCE
                  </span>
                </Link>
              </motion.div>
            )}

            {status === 'error' && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="flex flex-col items-center justify-center space-y-4"
              >
                <XCircle className="w-16 h-16 text-red-500" />
                <h3 className="text-xl font-bold text-white">Verification Failed</h3>
                <p className="text-sm text-red-400">
                  {errorMessage}
                </p>
                <Link
                  href="/auth/login"
                  className="btn-secondary w-full mt-4 flex justify-center py-2.5"
                >
                  RETURN TO LOGIN
                </Link>
              </motion.div>
            )}
          </div>
        </motion.div>
      </div>
    </div>
  );
}
