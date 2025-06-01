const webpack = require('webpack');

module.exports = function override(config, env) {
    config.plugins.push(new webpack.ProvidePlugin({
        process: 'process/browser.js',
	Buffer: ['buffer', 'Buffer']
    }));

    config.resolve.fallback = {
        "crypto": require.resolve("crypto-browserify"),
        "stream": require.resolve("stream-browserify"),
        "buffer": require.resolve("buffer/")
    };

    config.module.rules = [ ...config.module.rules, 
    {
        test: /falcon\.js$/,
        loader: `exports-loader`,
        options: {
          type: `module`,
          // this MUST be equivalent to EXPORT_NAME in packages/example-wasm/complile.sh
          exports: `Falcon`,
        },
      },
      // wasm files should not be processed but just be emitted and we want
      // to have their public URL.
      {
        test: /falcon\.wasm$/,
        type: `javascript/auto`,
        loader: `file-loader`,
        // options: {
        // if you add this, wasm request path will be https://domain.com/publicpath/[hash].wasm
        //   publicPath: `static/`,
        // },
      },	
    ];

    return config;
};

