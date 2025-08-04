const jsdom = require("jsdom");
const { JSDOM } = jsdom;

async function crawlPage(baseURL, currentURL, pages, crawledUrls) {
  console.log(`actively crawling ${currentURL}`);

  const baseURLObj = new URL(baseURL);
  const currentURLObj = new URL(currentURL);

  if (baseURLObj.hostname !== currentURLObj.hostname) {
    return { pages, crawledUrls };
  }

  const normalizedCurrentURL = normalizeURL(currentURL);
  if (pages[normalizedCurrentURL] > 0) {
    pages[normalizedCurrentURL]++;
    return { pages, crawledUrls };
  }
  pages[normalizedCurrentURL] = 1;

  try {
    const resp = await fetch(currentURL);

    if (resp.status > 399) {
      console.log(`❌ Error: ${resp.status} on ${currentURL}`);
      return { pages, crawledUrls };
    }

    const contentType = resp.headers.get("content-type");
    if (!contentType || !contentType.includes("text/html")) {
      console.log(`⚠️  Skipping non-HTML (${contentType}) on ${currentURL}`);
      return { pages, crawledUrls };
    }

    // ✅ Add to crawledUrls
    crawledUrls.push(currentURL);

    const htmlBody = await resp.text();
    const nextURLs = getURLsFromHTML(htmlBody, baseURL);
    for (const nextURL of nextURLs) {
      const result = await crawlPage(baseURL, nextURL, pages, crawledUrls);
      pages = result.pages;
      crawledUrls = result.crawledUrls;
    }
  } catch (error) {
    console.log(`❌ Fetch error: ${error.message}`);
  }

  return { pages, crawledUrls };
}

function getURLsFromHTML(htmlBody, baseURL) {
  const urls = [];
  const dom = new JSDOM(htmlBody);
  const linkElements = dom.window.document.querySelectorAll("a");

  for (const linkElement of linkElements) {
    const href = linkElement.href;

    try {
      const urlObj = href.startsWith("/")
        ? new URL(`${baseURL}${href}`)
        : new URL(href);

      urls.push(urlObj.href);
    } catch (err) {
      console.log(`❌ Invalid URL: ${err.message}`);
    }
  }

  dom.window.close();
  return urls;
}

function normalizeURL(urlString) {
  const urlObj = new URL(urlString);
  const hostPath = `${urlObj.hostname}${urlObj.pathname}`.replace(/\/+/g, "/");
  return hostPath.endsWith("/") ? hostPath.slice(0, -1) : hostPath;
}

module.exports = {
  normalizeURL,
  getURLsFromHTML,
  crawlPage,
};
