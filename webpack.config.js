const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  // Tell webpack where to start
  entry: './main.js',

  // Tell webpack where to put the final bundled files
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'main.js',
    // for GitHub pages deployment.
    publicPath: "/BitQuill/", 
  },

  // Configure the development server
  devServer: {
    // This tells the server to serve the files that webpack builds
    static: {
      directory: path.join(__dirname, 'dist'),
    },
    port: 8080,
    // This helps the server handle routing for single-page apps
    historyApiFallback: true,
  },

  module: {
    rules: [
      {
        test: /\.css$/i,
        use: ['style-loader', 'css-loader'],
      },
    ],
  },
  
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: "modern-styles.css", to: "modern-styles.css" },
        { from: "wasm", to: "wasm" }
      ],
    }),
    new HtmlWebpackPlugin({
        // This tells the plugin to use your existing index.html as a template
        template: 'index.html' 
    })
  ],
  
  // Set the mode and enable WASM support
  mode: 'development',
  experiments: {
    asyncWebAssembly: true,
  },
};
