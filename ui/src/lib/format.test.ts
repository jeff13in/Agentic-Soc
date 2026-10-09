import { describe, expect, it } from "vitest";
import { basename, num, pct, seconds, usd } from "./format";

describe("format", () => {
  it("formats rates and handles missing values", () => {
    expect(pct(0.889)).toBe("88.9%");
    expect(pct(null)).toBe("–");
    expect(pct(0)).toBe("0.0%");
  });
  it("formats numbers, money and durations", () => {
    expect(num(4.7)).toBe("4.7");
    expect(num(2940.4)).toBe("2,940");
    expect(usd(0)).toBe("$0");
    expect(usd(0.0042)).toBe("$0.0042");
    expect(usd(0.123)).toBe("$0.123");
    expect(seconds(0.081)).toBe("81 ms");
    expect(seconds(12.34)).toBe("12.3 s");
  });
  it("takes basenames of Windows paths", () => {
    expect(basename("C:\\Windows\\System32\\cmd.exe")).toBe("cmd.exe");
    expect(basename(null)).toBe("");
  });
});
