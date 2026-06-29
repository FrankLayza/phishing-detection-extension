import { extractPageFeatures } from "./fe.mjs";
const urls = ["https://www.google.com/","https://www.wikipedia.org/","https://github.com/FrankLayza","https://www.paypal.com/uk/home"];
for (const u of urls) {
  const f = extractPageFeatures(u, "");
  console.log("URL:", u);
  console.log(JSON.stringify(f));
}
