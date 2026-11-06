// Statuses the models answer with, and the error bodies they share.

import type { ErrorResponse, ValidationProblemResponse } from "./dto";
import type { MockReply } from "./http-mock";

export const HTTP_CREATED = 201;
export const HTTP_NO_CONTENT = 204;
export const HTTP_BAD_REQUEST = 400;
export const HTTP_UNAUTHORIZED = 401;
export const HTTP_NOT_FOUND = 404;
export const HTTP_CONFLICT = 409;

/** A refusal, in the shape every Bitwarden service refuses with. */
export function error(status: number, message: string): MockReply {
  const body: ErrorResponse = { message };

  return { status, json: body };
}

/**
 * A refusal in the RFC 7807 shape the newer endpoints use, carrying one machine-readable `code`
 * against the request `property` it concerns.
 */
export function validationProblem(property: string, code: string, detail: string): MockReply {
  const body: ValidationProblemResponse = {
    type: "validation_error",
    title: "One or more validation errors occurred.",
    status: HTTP_BAD_REQUEST,
    errors: { [property]: [{ type: code, detail }] },
  };

  return { status: HTTP_BAD_REQUEST, json: body };
}
