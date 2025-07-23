const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = {
  // 1. Tell webpack where to start
  entry: './main.js',

  // 2. Tell webpack where to put the final bundled files
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'main.js',
    workerPublicPath: '/',
  },

  // 3. Configure the development server
  devServer: {
    // Serve files from the project root. This is simpler.
    static: {
      directory: path.join(__dirname, '.'),
    },
    port: 8080,
  },

  // 4. Set the mode and enable WASM support
  mode: 'development',
  experiments: {
    asyncWebAssembly: true,
  },
};
