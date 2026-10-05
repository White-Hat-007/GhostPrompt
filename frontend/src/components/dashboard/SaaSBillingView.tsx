'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  CreditCard, TrendingUp, Users, Zap, BarChart3, ArrowUpRight,
  DollarSign, Clock, Loader2, CheckCircle, RefreshCw, Shield,
} from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

interface SaaSBillingViewProps {
  token?: string;
}

const PLAN_TIERS = [
  { key: 'free', name: 'Starter', price: 0, scans: '1,000/mo', models: 3, users: 1, features: ['Basic Detection', 'Dashboard', 'Email Alerts'] },
  { key: 'pro', name: 'Pro', price: 49, scans: '50,000/mo', models: 10, users: 5, features: ['All Detection Engines', 'ATLAS Mapping', 'API Access', 'Priority Support'] },
  { key: 'business', name: 'Business', price: 199, scans: '500,000/mo', models: 50, users: 25, features: ['Everything in Pro', 'Custom Models', 'Federation', 'SSO/SAML', 'SLA 99.99%', 'Dedicated Support'] },
  { key: 'enterprise', name: 'Enterprise', price: -1, scans: 'Unlimited', models: 999, users: 999, features: ['Dedicated Infrastructure', 'On-Prem Option', 'Custom Integrations', 'White-Label'] },
];

interface SubscriptionData {
  plan: string;
  status: string;
  scan_usage: number;
  scan_limit: number;
  usage_pct: number;
  seats_used: number;
  seats_limit: number;
  billing_period: { start: string | null; end: string | null };
}

export default function SaaSBillingView({ token }: SaaSBillingViewProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'plans' | 'invoices'>('overview');
  const [subscription, setSubscription] = useState<SubscriptionData | null>(null);
  const [loading, setLoading] = useState(true);
  const [upgrading, setUpgrading] = useState<string | null>(null);

  const authHeaders = useCallback(() => {
    const t = token || (typeof window !== 'undefined' ? localStorage.getItem('access_token') : null);
    return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
  }, [token]);

  const fetchBilling = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/billing/usage`, { headers: authHeaders() });
      if (res.ok) {
        setSubscription(await res.json());
      }
    } catch (err) {
      console.error('Failed to fetch billing:', err);
    } finally {
      setLoading(false);
    }
  }, [authHeaders]);

  useEffect(() => { fetchBilling(); }, [fetchBilling]);

  const upgradePlan = async (planKey: string) => {
    setUpgrading(planKey);
    try {
      const res = await fetch(`${API}/api/v1/billing/checkout`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          plan: planKey,
          success_url: `${window.location.origin}/dashboard?billing=success`,
          cancel_url: `${window.location.origin}/dashboard?billing=cancel`,
          bypass_mode: true,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        // In bypass mode, the upgrade is instant
        await fetchBilling();
      }
    } catch (err) {
      console.error(err);
    }
    setUpgrading(null);
  };

  const currentPlan = subscription?.plan || 'free';
  const scanUsage = subscription?.scan_usage || 0;
  const scanLimit = subscription?.scan_limit || 1000;
  const usagePct = subscription?.usage_pct || 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-ghost-400 animate-spin" />
      </div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white">Usage & Billing</h2>
          <p className="text-sm text-gray-500 mt-1">Plan management, usage tracking, and billing (bypass mode — no payment required)</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/15 px-3 py-1.5 rounded-lg capitalize">
            {currentPlan} Plan
          </span>
          <button onClick={fetchBilling} className="btn-ghost text-[10px] gap-1">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-lg bg-surface-1/50 border border-white/[0.04] w-fit">
        {(['overview', 'plans', 'invoices'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-md text-xs font-medium transition-all capitalize ${
              activeTab === tab ? 'bg-ghost-600/20 text-ghost-400' : 'text-gray-500 hover:text-gray-300'
            }`}
          >{tab}</button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Usage Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { label: 'Scans Used', value: scanUsage.toLocaleString(), sub: `of ${scanLimit > 0 ? scanLimit.toLocaleString() : '∞'}`, icon: Zap, color: 'text-ghost-400' },
              { label: 'Usage', value: `${usagePct.toFixed(1)}%`, sub: 'of limit', icon: BarChart3, color: usagePct > 80 ? 'text-red-400' : 'text-emerald-400' },
              { label: 'Seats', value: `${subscription?.seats_used || 1}`, sub: `of ${(subscription?.seats_limit || 1) > 0 ? subscription?.seats_limit : '∞'}`, icon: Users, color: 'text-cyan-400' },
              { label: 'Status', value: subscription?.status || 'active', sub: '', icon: CheckCircle, color: 'text-emerald-400' },
            ].map((s, i) => (
              <div key={i} className="glass-card p-4">
                <div className="flex items-center gap-2 mb-2">
                  <s.icon className={`w-4 h-4 ${s.color}`} />
                  <span className="text-[10px] text-gray-500 uppercase tracking-wider">{s.label}</span>
                </div>
                <div className="flex items-baseline gap-1">
                  <p className="text-2xl font-bold text-white font-mono capitalize">{s.value}</p>
                  {s.sub && <span className="text-[10px] text-gray-600">{s.sub}</span>}
                </div>
              </div>
            ))}
          </div>

          {/* Usage Bar */}
          <div className="glass-card p-6">
            <h3 className="text-sm font-semibold text-white mb-4">Scan Usage This Period</h3>
            <div className="w-full h-4 rounded-full bg-surface-3 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  usagePct > 90 ? 'bg-gradient-to-r from-red-600 to-red-400' :
                  usagePct > 70 ? 'bg-gradient-to-r from-amber-600 to-amber-400' :
                  'bg-gradient-to-r from-ghost-600 to-ghost-400'
                }`}
                style={{ width: `${Math.min(usagePct, 100)}%` }}
              />
            </div>
            <div className="flex items-center justify-between mt-2 text-[10px] text-gray-500 font-mono">
              <span>{scanUsage.toLocaleString()} scans</span>
              <span>{scanLimit > 0 ? `${scanLimit.toLocaleString()} limit` : 'Unlimited'}</span>
            </div>
          </div>

          {/* Bypass mode notice */}
          <div className="glass-card p-4 border-l-2 border-ghost-500/40">
            <div className="flex items-start gap-3">
              <Shield className="w-5 h-5 text-ghost-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-white">Bypass Mode Active</p>
                <p className="text-xs text-gray-500 mt-1">
                  Stripe payment processing is bypassed. Plan upgrades are instant without payment.
                  To enable real billing, configure STRIPE_SECRET_KEY in the backend environment.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'plans' && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {PLAN_TIERS.map((plan) => {
            const isCurrent = plan.key === currentPlan;
            return (
              <div key={plan.key} className={`glass-card p-6 relative overflow-hidden ${isCurrent ? 'border-ghost-500/30' : ''}`}>
                {isCurrent && (
                  <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-ghost-500 to-cyber-500" />
                )}
                <h3 className="text-lg font-bold text-white">{plan.name}</h3>
                <div className="mt-2 mb-4">
                  {plan.price === -1 ? (
                    <span className="text-2xl font-bold text-gray-400">Custom</span>
                  ) : (
                    <div className="flex items-baseline gap-1">
                      <span className="text-3xl font-bold text-white font-mono">${plan.price}</span>
                      <span className="text-xs text-gray-500">/mo</span>
                    </div>
                  )}
                </div>
                <div className="space-y-2 mb-6">
                  <p className="text-[10px] text-gray-500 flex justify-between"><span>Scans</span><span className="text-gray-300 font-mono">{plan.scans}</span></p>
                  <p className="text-[10px] text-gray-500 flex justify-between"><span>Models</span><span className="text-gray-300 font-mono">{plan.models}</span></p>
                  <p className="text-[10px] text-gray-500 flex justify-between"><span>Users</span><span className="text-gray-300 font-mono">{plan.users}</span></p>
                </div>
                <ul className="space-y-1.5 mb-6">
                  {plan.features.map((f, j) => (
                    <li key={j} className="text-[11px] text-gray-400 flex items-center gap-2">
                      <span className="w-1 h-1 rounded-full bg-ghost-400" /> {f}
                    </li>
                  ))}
                </ul>
                <button
                  onClick={() => !isCurrent && plan.price !== -1 && upgradePlan(plan.key)}
                  disabled={isCurrent || upgrading === plan.key}
                  className={`w-full py-2 rounded-lg text-xs font-semibold transition-all ${
                    isCurrent ? 'bg-ghost-600/20 text-ghost-400 border border-ghost-500/20' :
                    'bg-surface-2 text-gray-400 border border-white/[0.06] hover:border-white/[0.1] hover:text-white'
                  }`}
                >
                  {upgrading === plan.key ? (
                    <Loader2 className="w-3 h-3 animate-spin inline" />
                  ) : isCurrent ? 'Current Plan' : plan.price === -1 ? 'Contact Sales' : 'Upgrade (Bypass)'}
                </button>
              </div>
            );
          })}
        </div>
      )}

      {activeTab === 'invoices' && (
        <div className="glass-card overflow-hidden">
          <div className="px-5 py-3 border-b border-white/[0.04]">
            <h3 className="text-sm font-semibold text-white">Invoice History</h3>
          </div>
          <div className="px-5 py-8 text-center text-sm text-gray-600">
            No invoices yet. Billing is in bypass mode — upgrade plans instantly without payment.
          </div>
        </div>
      )}
    </motion.div>
  );
}
