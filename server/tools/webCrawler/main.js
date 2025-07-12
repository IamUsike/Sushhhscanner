/* There are mainly 3 steps when doing test driven development 
 - Stub out the function that needs to be tested 
 - Write the tests for the function 
 - Implement the function 
 */

const {printReport} = require("./report.js")
const { crawlPage } = require("./crawler.js");
async function main() {
  if (process.argv.length < 3) {
    console.log("No website provided");
    process.exit(1);
  }
  if (process.argv.length > 3) {
    console.log("too many args provided");
    process.exit(1);
  }
  const baseURL = process.argv[2];

  console.log(`Starting  crawl`);
  const pages = await crawlPage(baseURL, baseURL, {});
  printReport(pages)
  
}

main();
