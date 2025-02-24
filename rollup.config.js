import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from '@rollup/plugin-typescript';
import json from '@rollup/plugin-json';
import wasm from '@rollup/plugin-wasm';

export default {
    input: 'index.ts', // your entry point
    plugins: [
        json(),
        resolve({
            browser: true, // ensures that browser fields are used
            extensions: ['.js', '.ts']
          }),     // resolves node_modules imports
        commonjs(),    // converts CommonJS modules to ES6, if needed
        typescript(),
        wasm({
            maxFileSize: 10000000, // inline all wasm files up to 10MB
        })
    ],
    external: [ 'path', 'fs', 'os', 'builtin-modules', 'resolve', 'browser-resolve', 'is-module', 'rollup-pluginutils' ],
    output: [
        {
            file: 'dist/bonsai-sdk.esm.js',
            format: 'esm', // ES module output
            sourcemap: true
        },
        {
            file: 'dist/bonsai-sdk.cjs.js',
            format: 'cjs', // CommonJS output
            sourcemap: true
        }
    ]
};
