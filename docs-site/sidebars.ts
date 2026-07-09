import type { SidebarsConfig } from '@docusaurus/plugin-content-docs'

const sidebars: SidebarsConfig = {
  gatewaySidebar: [
    'intro',
    'getting-started',
    {
      type: 'category',
      label: 'Архитектура',
      collapsed: false,
      items: [
        'architecture/overview',
        'architecture/authn',
        'architecture/authz',
        'architecture/routing',
        'architecture/internal-cache',
      ],
    },
    {
      type: 'category',
      label: 'Установка',
      collapsed: true,
      items: ['install/deploy', 'install/configuration'],
    },
    {
      type: 'category',
      label: 'API',
      collapsed: false,
      items: ['api/overview', 'api/operations', 'api/internal-authz-cache'],
    },
  ],
}

export default sidebars
