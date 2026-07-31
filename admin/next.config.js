// @ts-check

const isProduction = process.env.NODE_ENV === "production";

/**
 * @type {import('next').NextConfig}
 **/
const nextConfig = {
  reactStrictMode: true,
  trailingSlash: true,

  // The admin UI ships as static files embedded into the hetty binary, so
  // there is no Next.js server at runtime. Next 13 removed the separate
  // `next export` command in favour of this flag, which makes `next build`
  // emit the static site directly.
  //
  // Production only: `output: "export"` is incompatible with rewrites, and the
  // rewrite below is what lets `next dev` reach a hetty running on 8080.
  ...(isProduction
    ? { output: /** @type {const} */ ("export") }
    : {
        async rewrites() {
          return [
            {
              source: "/api/:path*",
              destination: "http://localhost:8080/api/:path*",
            },
          ];
        },
      }),
};

module.exports = nextConfig;
