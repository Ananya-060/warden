export class WardenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WardenError';
  }
}

export class ToolNotTrustedError extends WardenError {
  constructor(reason: string) {
    super(reason);
    this.name = 'ToolNotTrustedError';
  }
}

export class AuthError extends WardenError {
  constructor(message = 'Invalid or missing API Key') {
    super(message);
    this.name = 'AuthError';
  }
}

export class APIError extends WardenError {
  constructor(message: string, public readonly status?: number) {
    super(message);
    this.name = 'APIError';
  }
}
