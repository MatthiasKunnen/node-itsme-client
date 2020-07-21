function mapFilenames(filenames) {
    return filenames.map(filename => `"${filename}"`).join(' ');
}

module.exports = {
    'src/**/*.ts': (filenames) => [
        `eslint --fix --cache ${mapFilenames(filenames)}`,
        `tsc -p tsconfig.json`,
        `yarn run build`,
    ],
};
