const jsdom = require("jsdom");
const { JSDOM } = jsdom; //allows node to access dom apis

async function crawlPage(baseURL, currentURL, pages) {
  //pages object keeps track of all the pages that we have crawled so far
  console.log(`actively crawling ${currentURL}`);

  //check if the current url and baseURl are in the same domain
  const baseURLObj = new URL(baseURL);
  const currentURLObj = new URL(currentURL);

  if (baseURLObj.hostname !== currentURLObj.hostname) {
    return pages;
  }

  //check if we've already crawled a page ... if the normalized url exists in the pages object
  const normalizedCurrentURL = normalizeURL(currentURL);
  if (pages[normalizedCurrentURL] > 0) {
    pages[normalizedCurrentURL]++;
    return pages;
  }
  pages[normalizedCurrentURL] = 1;

  try {
    const resp = await fetch(currentURL);

    if (resp.status > 399) {
      console.log(
        `Error in fetch with status code: ${resp.status} on page: ${currentURL} `
      );
      return pages;
    }

    const contentType = resp.headers.get("content-type");
    // console.log(resp.headers)
    if (!contentType || !contentType.includes("text/html")) {
      console.log(
        `non html response, content type ${contentType}, on page: ${currentURL}`
      );
      return pages;
    }

    const htmlBody = await resp.text();
    const nextURLs = getURLsFromHTML(htmlBody, baseURL);
    //recursively crawl the pages
    for (const nextURL of nextURLs) {
      // console.log(`next url is ${nextURL}`)
      pages = await crawlPage(baseURL, nextURL, pages);
    }
  } catch (error) {
    console.log(`Error in fetch: ${error.message}`);
  }
  return pages;
}

function getURLsFromHTML(htmlBody, baseURL) {
  const urls = [];
  const dom = new JSDOM(htmlBody);
  const linkElements = dom.window.document.querySelectorAll("a"); 
  for (const linkElement of linkElements) {
    if (linkElement.href.slice(0, 1) === "/") {
      //relative URL
      try {
        const urlObj = new URL(`${baseURL}${linkElement.href}`);  
        urls.push(urlObj.href);
      } catch (err) {
        console.log(`Error with relative URLs: ${err.message}`);
      }
    } else {
      //absolute URLs
      try {
        const urlObj = new URL(linkElement.href);
        urls.push(urlObj.href);
      } catch (error) {
        console.log(`Fucked up absolute URL: ${error.message}`);
      } finally {
        if (dom) {
          dom.window.close(); // Clean up JSDOM
        }
      }
    }
  }
  // console.log(`html, ${urls}`)
  return urls;
}

/* 1. There may be different url pointing to the same page 
    we need to normalize those 
    2. Strip the trailing slash*/

function normalizeURL(urlString) {
  const urlObj = new URL(urlString);
  // Combine hostname and pathname, then replace any double slashes with single slash
  const hostPath = `${urlObj.hostname}${urlObj.pathname}`.replace(/\/+/g, "/");
  if (hostPath.length > 0 && hostPath.slice(-1) === "/") {
    return hostPath.slice(0, -1);
  }
  return hostPath;
}

module.exports = {
  normalizeURL,
  getURLsFromHTML,
  crawlPage,
};
