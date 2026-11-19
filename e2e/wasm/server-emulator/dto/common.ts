// Shapes and helpers every feature's request and response models share.

import { asEncString } from "../../tests/type-assertion-helpers";

export function optionalString(value: { toString(): string } | null | undefined): string | null {
  return value === null || value === undefined ? null : String(value);
}

export function optionalEnc(value: string | null | undefined) {
  return value === null || value === undefined ? undefined : asEncString(value);
}

/** What the server answers with when it refuses. */
export class ErrorResponse {
  message!: string;
  validationErrors?: Record<string, string[]>;
}

/** `ListResponseModel<T>`. */
export class ListResponse<T> {
  object!: "list";
  data!: T[];
  continuationToken!: null;

  static of<T>(data: T[]): ListResponse<T> {
    return { object: "list", data, continuationToken: null };
  }
}
