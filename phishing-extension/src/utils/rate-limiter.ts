export class RateLimiter {
  private timestamps: number[] = [];
  
  constructor(private maxRequests: number, private windowMs: number) {}

  canMakeRequest(): boolean {
    const now = Date.now();
    // Remove old timestamps outside the window
    this.timestamps = this.timestamps.filter(t => now - t < this.windowMs);
    
    if (this.timestamps.length >= this.maxRequests) {
      return false;
    }
    
    this.timestamps.push(now);
    return true;
  }
}

// Global instance: 10 requests per minute
export const apiRateLimiter = new RateLimiter(10, 60000);
