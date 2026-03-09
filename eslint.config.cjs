const config = require('@silvermine/eslint-config'),
      node = require('@silvermine/eslint-config/partials/node');

module.exports = [
   {
      ignores: [
         'dist-js/**',
         'src-tauri/**',
         'examples/**',
      ],
   },
   ...config,
   { ...node },
   {
      files: [ '**/*.ts' ],
      rules: {
         'no-console': [ 'error', { allow: [ 'debug', 'info', 'warn', 'error', 'table' ] } ],
      },
   },
];
