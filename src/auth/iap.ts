import { logger } from '../logging/logging.js';

export interface IAPUser {
  email: string;
  id: string;
}

/**
 * Extracts the user email from IAP headers.
 * IAP provides headers like:
 * x-goog-authenticated-user-email: accounts.google.com:user@example.com
 * x-goog-authenticated-user-id: accounts.google.com:123456789
 */
export function getIAPUser(headers: Record<string, string | string[] | undefined>): IAPUser | null {
  const emailHeader = headers['x-goog-authenticated-user-email'];
  const idHeader = headers['x-goog-authenticated-user-id'];

  if (!emailHeader || typeof emailHeader !== 'string') {
    return null;
  }

  const id = typeof idHeader === 'string' ? idHeader : '';

  // Strip the prefix (e.g., "accounts.google.com:")
  const email = emailHeader.includes(':') ? emailHeader.split(':')[1] : emailHeader;

  return { email, id };
}

/**
 * Validates the IAP JWT assertion if present.
 * For production, you should verify the JWT signature using Google's public keys.
 * For now, we'll just log its presence as this is a starting point.
 */
export function validateIAP(headers: Record<string, string | string[] | undefined>): boolean {
  const jwt = headers['x-goog-iap-jwt-assertion'];
  if (jwt) {
    logger.debug('IAP JWT assertion found');
    // In a real implementation, you would verify this JWT.
    return true;
  }
  return false;
}
