/* There are mainly 3 steps when doing test driven development 
 - Stub out the function that needs to be tested 
 - Write the tests for the function 
 - Implement the function 
 */

const { printReport } = require("./report.js");
const { crawlPage } = require("./crawler.js");
const axios = require("axios");

async function main() {
  if (process.argv.length < 3) {
    console.log("❌ No website provided");
    process.exit(1);
  }
  if (process.argv.length > 3) {
    console.log("❌ Too many args provided");
    process.exit(1);
  }

  const baseURL = process.argv[2];
  console.log(`🚀 Starting crawl for: ${baseURL}`);

  // 👇 Updated call to handle both pages and crawledUrls
  const { pages, crawledUrls } = await crawlPage(baseURL, baseURL, {}, []);

  // ✅ Print crawl summary
  printReport(pages);
  console.log(`🕸️  Total crawled URLs: ${crawledUrls.length}`);

  // 👇 Send to ML API Predictor
  try {
    const res = await axios.post("http://localhost:5000/add_crawl_data", {
      urls: crawledUrls,
      metadata: [], // Optional, skip if not collecting
    });

    console.log("✅ Sent to ML model:", res.data);
  } catch (err) {
    console.error("❌ Failed to send to ML model:", err.message);
  }
}

main();
