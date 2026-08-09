package builtin

// popularNpm is a SEED corpus of high-download npm package names used as the
// typosquat reference set (VC-006). A name close to one of these but not equal
// is suspicious; a name equal to one of these is treated as legitimate.
//
// This is intentionally a small, static, embedded list for v0 — enough to catch
// squats on the most-attacked packages without a network call. A future drop
// can swap this for a periodically-refreshed top-N list loaded from cache.
var popularNpm = []string{
	"lodash", "react", "react-dom", "express", "chalk", "commander", "debug",
	"async", "request", "axios", "moment", "underscore", "bluebird", "yargs",
	"glob", "minimist", "colors", "mkdirp", "through2", "body-parser", "uuid",
	"semver", "webpack", "rimraf", "prop-types", "classnames", "redux",
	"react-redux", "eslint", "prettier", "typescript", "babel-core", "core-js",
	"regenerator-runtime", "tslib", "rxjs", "jquery", "vue", "angular", "next",
	"dotenv", "cross-env", "node-fetch", "got", "cheerio", "ws", "socket.io",
	"mongoose", "mongodb", "mysql", "pg", "redis", "sequelize", "knex",
	"nodemon", "pm2", "winston", "morgan", "cors", "helmet", "passport",
	"jsonwebtoken", "bcrypt", "bcryptjs", "cookie-parser", "multer", "nanoid",
	"date-fns", "dayjs", "immer", "formik", "yup", "zod", "ajv", "joi",
	"inquirer", "ora", "chokidar", "fs-extra", "execa", "shelljs", "tar",
	"node-gyp", "ejs", "handlebars", "pug", "marked", "highlight.js", "dompurify",
	"validator", "qs", "url", "util", "path-to-regexp", "send", "mime",
	"mime-types", "content-type", "raw-body", "type-is", "on-finished",
	"finalhandler", "serve-static", "etag", "fresh", "range-parser", "vary",
	"jest", "mocha", "chai", "sinon", "supertest", "nyc", "ts-node", "esbuild",
	"rollup", "vite", "postcss", "autoprefixer", "sass", "less", "tailwindcss",
	"styled-components", "emotion", "storybook", "enzyme", "puppeteer",
	"playwright", "selenium-webdriver", "graphql", "apollo-server",
	"apollo-client", "prisma", "typeorm", "class-validator", "reflect-metadata",
	"aws-sdk", "google-auth-library", "stripe", "twilio", "nodemailer",
	"sharp", "jimp", "canvas", "pdfkit", "xlsx", "csv-parse", "papaparse",
	"cli-table", "figlet", "boxen", "signale", "consola", "pino",
}

// popularNpmSet is the corpus as a lookup set (populated once).
var popularNpmSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(popularNpm))
	for _, n := range popularNpm {
		m[n] = struct{}{}
	}
	return m
}()
