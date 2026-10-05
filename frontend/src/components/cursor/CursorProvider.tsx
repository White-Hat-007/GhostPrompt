'use client';

import dynamic from 'next/dynamic';

const GhostCursor = dynamic(() => import('@/components/cursor/GhostCursor'), {
  ssr: false,
});

export default function CursorProvider() {
  return <GhostCursor />;
}
