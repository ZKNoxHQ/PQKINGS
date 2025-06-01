const webpack = require('webpack');

module.exports = function override(config, env) {
    config.plugins.push(new webpack.ProvidePlugin({
        process: 'process/browser.js',
    }));

    config.resolve.fallback = {
        "crypto": require.resolve("crypto-browserify"),
        "stream": require.resolve("stream-browserify"),
        "buffer": require.resolve("buffer/")
    };

    return config;
};
