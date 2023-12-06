const path = require('path');

module.exports = {
  mode: 'development',
  devtool: 'source-map',
  entry: './src/background.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'background.bundle.js'
  },
  module: {
    rules: [
      {
        test: /\.(ts|tsx)$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader'
        }
      }
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
  },
};
