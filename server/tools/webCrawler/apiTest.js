const axios = require("axios");

const crawledUrls = [
  "https://example.com/api/v1/users",
  "https://example.com/api/v1/products",
  "https://example.com/admin/settings",
];

axios
  .post("http://localhost:5000/add_crawl_data", {
    urls: crawledUrls,
    metadata: [],
  })
  .then((res) => {
    console.log("✅ Successfully added:", res.data);
  })
  .catch((err) => {
    console.error("❌ Error:", err.message);
  });
