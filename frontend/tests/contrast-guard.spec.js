import { test, expect } from "@playwright/test";
import path from "node:path";
import { pathToFileURL } from "node:url";

const lime = "rgb(200, 255, 61)";
const pages = [
  "/",
  "/dashboard",
  "/history",
  "/education",
  "/lists",
  "/login",
  "/register",
  "/forum",
];
const extensionPages = [
  "popup.html",
  "settings.html",
  "onboarding.html",
  "warning.html",
];

function contrastRatio(foreground, background) {
  const channel = (value) => {
    const normalized = value / 255;
    return normalized <= 0.03928
      ? normalized / 12.92
      : ((normalized + 0.055) / 1.055) ** 2.4;
  };
  const rgb = (value) => value.match(/\d+/g).slice(0, 3).map(Number);
  const luminance = (value) => {
    const [r, g, b] = rgb(value).map(channel);
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const light = Math.max(luminance(foreground), luminance(background));
  const dark = Math.min(luminance(foreground), luminance(background));
  return (light + 0.05) / (dark + 0.05);
}

for (const colorScheme of ["light", "dark"]) {
  test.describe(`${colorScheme} extension accent surfaces`, () => {
    for (const screen of extensionPages) {
      test(`${screen} keeps lime text readable`, async ({ page }) => {
        await page.emulateMedia({ colorScheme });
        await page.goto(
          pathToFileURL(path.resolve(process.cwd(), "..", "extension", screen))
            .href,
        );
        if (colorScheme === "dark")
          await page.evaluate(() => {
            document.documentElement.dataset.theme = "dark";
          });
        const failures = await page
          .locator("*")
          .evaluateAll(
            (elements, limeColor) =>
              elements
                .filter(
                  (element) =>
                    getComputedStyle(element).backgroundColor === limeColor,
                )
                .map((element) => ({
                  tag: element.tagName,
                  text: element.textContent?.trim().slice(0, 60),
                  color: getComputedStyle(element).color,
                })),
            lime,
          );
        for (const failure of failures) {
          expect(contrastRatio(failure.color, lime)).toBeGreaterThanOrEqual(
            4.5,
          );
        }
      });
    }
  });
}

for (const colorScheme of ["light", "dark"]) {
  test.describe(`${colorScheme} accent surfaces`, () => {
    for (const route of pages) {
      test(`${route} keeps lime text readable`, async ({ page }) => {
        await page.emulateMedia({ colorScheme });
        await page.goto(route);
        const failures = await page
          .locator("*")
          .evaluateAll(
            (elements, limeColor) =>
              elements
                .filter(
                  (element) =>
                    getComputedStyle(element).backgroundColor === limeColor,
                )
                .map((element) => ({
                  tag: element.tagName,
                  text: element.textContent?.trim().slice(0, 60),
                  color: getComputedStyle(element).color,
                })),
            lime,
          );
        for (const failure of failures) {
          expect(contrastRatio(failure.color, lime)).toBeGreaterThanOrEqual(
            4.5,
          );
        }
      });
    }
  });
}
