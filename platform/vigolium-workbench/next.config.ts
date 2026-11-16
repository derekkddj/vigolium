import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  allowedDevOrigins: ['host.docker.internal', 'local-testing.vigolium.com'],
  output: 'export',
  distDir: 'dist',
  trailingSlash: true,
  skipTrailingSlashRedirect: false,
  // Keep static-export workers bounded on high-core development hosts.
  experimental: {
    cpus: 2,
  },
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
