// A frontend bundle fragment with known answers, used to check that the web
// tools find what they claim to: endpoints, a leaked key, a JWT.
const API = "https://api.example.com/v2";
const CDN = "//cdn.example.net/static/app.js";

export async function login(user, pass) {
  return fetch("https://api.example.com/v2/login?client=web", {
    method: "POST",
    body: JSON.stringify({ user, pass }),
  });
}

export const profile = () => axios.get("/api/v2/profile");
export const avatar = () => "/assets/avatar.png";
export const favicon = () => "/favicon.ico";
export const sessions = () => "/api/v2/sessions?page=1&size=20";
export const graph = gql`query GetProfile { me { id } }`;

// Secrets and a token that should never have been committed. The Stripe shape
// is deliberately absent: a live-looking key in a public repository is exactly
// what GitHub's push protection blocks, so that rule is unit-tested with a
// value built at runtime instead.
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const DB = { password: "hunter2hunter2" };
const NONCE = "Zk9xS2pM4vQ8wR1tY6uI0oP3aS7dF5gH2jK4lN6bV8cX";

// jwt.io's example token, signed with "your-256-bit-secret".
const TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
