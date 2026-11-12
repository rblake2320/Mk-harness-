/**
 * The app's single API client (shared SDK) and build configuration.
 * `extra.apiUrl` is the FastAPI origin; `extra.webUrl` is the web app that hosts the
 * passkey approval page (its origin must be one of the kernel's MK_APPROVAL_ORIGINS).
 */
import Constants from 'expo-constants';
import { MKClient, validateWebUrl } from '../../packages/sdk/src/index';

const extra = (Constants.expoConfig?.extra ?? {}) as { apiUrl?: unknown; webUrl?: unknown };

export const API_URL = typeof extra.apiUrl === 'string' ? extra.apiUrl : 'http://localhost:8000';
/** Null when not configured or not HTTPS (loopback http is accepted in development builds only). */
export const WEB_URL: string | null = validateWebUrl(extra.webUrl, { allowDevHttp: __DEV__ });

export const client = new MKClient(API_URL);
