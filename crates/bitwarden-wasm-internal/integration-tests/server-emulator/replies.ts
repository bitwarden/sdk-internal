// Statuses the models answer with, and the error body they share.

import type { ErrorResponse } from "./dto";
import type { MockReply } from "./http-mock";

export const HTTP_BAD_REQUEST = 400;
export const HTTP_UNAUTHORIZED = 401;
export const HTTP_NOT_FOUND = 404;
export const HTTP_CONFLICT = 409;

/** A refusal, in the shape every Bitwarden service refuses with. */
export function error(status: number, message: string): MockReply {
  const body: ErrorResponse = { message };

  return { status, json: body };
}
