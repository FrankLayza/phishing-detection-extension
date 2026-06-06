import type { DetectionResult } from "../types";

export class ResultCache {
  private cache: Map<string, DetectionResult> = new Map();
  private ttlMs: number = 1000 * 60 * 60; // 1 hour caching

  set(url: string, result: DetectionResult) {
    this.cache.set(url, result);
  }

  get(url: string): DetectionResult | null {
    const cached = this.cache.get(url);
    if (!cached) return null;

    if (Date.now() - cached.timestamp > this.ttlMs) {
      this.cache.delete(url);
      return null;
    }
    return cached;
  }

  clear() {
    this.cache.clear();
  }
}

export const urlCache = new ResultCache();
