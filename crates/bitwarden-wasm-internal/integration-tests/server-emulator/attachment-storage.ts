// An in-memory model of the blob storage attachment files live in.
//
// The api server never serves a file itself: it answers with a download URL, and the client fetches
// the encrypted bytes from storage. Storage URLs are pre-signed, so its route is unauthenticated.

import type { Cipher } from "@bitwarden/sdk-internal";

import type { Database } from "./database";
import type { MockReply, Routes } from "./http-mock";

import { error, HTTP_NOT_FOUND } from "./replies";
import { ATTACHMENTS_URL } from "./urls";

/** The key a file is stored under: attachment ids are only unique within their cipher. */
export const attachmentFileKey = (cipherId: string, attachmentId: string): string =>
  `${cipherId}/${attachmentId}`;

export class AttachmentStorage {
  constructor(private readonly db: Database) {}

  routes(): Routes {
    return {
      "GET /attachments/:cipherId/:attachmentId": (request) =>
        this.download(request.params.cipherId, request.params.attachmentId),
    };
  }

  /**
   * The `AttachmentResponseModel` for an attachment of `cipher`, carrying the URL its file
   * downloads from, or a 404 when the cipher has no such attachment or no file was stored for it.
   */
  static attachmentData(db: Database, cipher: Cipher, attachmentId: string): MockReply {
    const cipherId = String(cipher.id);
    const attachment = cipher.attachments?.find((candidate) => candidate.id === attachmentId);
    if (
      attachment === undefined ||
      !db.attachmentFiles.has(attachmentFileKey(cipherId, attachmentId))
    ) {
      return error(HTTP_NOT_FOUND, `no attachment ${attachmentId} on cipher ${cipherId}`);
    }

    return {
      json: {
        object: "attachment",
        id: attachment.id,
        url: `${ATTACHMENTS_URL}/attachments/${cipherId}/${attachmentId}`,
        fileName: attachment.fileName,
        key: attachment.key,
        size: attachment.size,
        sizeName: attachment.sizeName,
      },
    };
  }

  private download(cipherId: string, attachmentId: string): MockReply {
    const contents = this.db.attachmentFiles.get(attachmentFileKey(cipherId, attachmentId));
    if (contents === undefined) {
      return error(HTTP_NOT_FOUND, `no file for attachment ${attachmentId} on cipher ${cipherId}`);
    }

    return { bytes: contents };
  }
}
