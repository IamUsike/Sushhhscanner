const { test, expect } = require("@jest/globals");
const {sortPages} = require('./report.js')


test("sort pages", () => {
  const input = {
    'https://wagslane.com':1,
    'https://wagslane.com/path':9,
    'https://wagslane.com/path1':7,
    'https://wagslane.com/path2':16,
    'https://wagslane.com/path3':5,
  };
  const actual = sortPages(input);
  const expected = [
    ['https://wagslane.com/path2', 16],
    ['https://wagslane.com/path', 9],
    ['https://wagslane.com/path1', 7],
    ['https://wagslane.com/path3', 5],
    ['https://wagslane.com', 1]
  ];
  expect(actual).toEqual(expected);
});