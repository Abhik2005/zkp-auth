import { defineConfig } from 'vitepress';

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: 'ZKP Auth',
  description:
    'Zero-Knowledge Proof authentication — Schnorr Proof of Knowledge on Ed25519. Passwords never leave the browser.',

  // GitHub Pages deployment: set base to your repo name if deploying to
  // https://<user>.github.io/<repo>/
  // base: '/zkp-auth/',

  head: [
    ['meta', { name: 'theme-color', content: '#646cff' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'ZKP Auth' }],
    [
      'meta',
      {
        property: 'og:description',
        content: 'Zero-Knowledge Proof authentication. Schnorr on Ed25519. Passwords never leave the browser.',
      },
    ],
  ],

  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    logo: { light: '/logo.svg', dark: '/logo-dark.svg', alt: 'ZKP Auth logo' },

    nav: [
      { text: 'Getting Started', link: '/' },
      { text: 'How It Works', link: '/how-it-works' },
      { text: 'API Reference', link: '/api-reference' },
      { text: 'Security', link: '/security' },
      { text: 'Migration', link: '/migration' },
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'Getting Started', link: '/' },
          { text: 'How It Works', link: '/how-it-works' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'API Reference', link: '/api-reference' },
          { text: 'Security Model', link: '/security' },
          { text: 'Migration Guide', link: '/migration' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/your-org/zkp-auth' },
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024 ZKP Auth contributors',
    },

    editLink: {
      pattern: 'https://github.com/your-org/zkp-auth/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },

    search: {
      provider: 'local',
    },
  },

  markdown: {
    // Syntax highlighting theme
    theme: {
      light: 'github-light',
      dark: 'github-dark',
    },
  },
});
